import os
import re
import sys
import time
import signal
import traceback
import logging
import requests
import json
import boto3
import subprocess
import six
import warnings
import pkgutil
from localstack import constants, config
from localstack.config import *
from localstack.utils.aws import aws_stack
from localstack.utils import common, persistence
from localstack.utils.common import *
from localstack.utils.analytics import event_publisher
from localstack.services import generic_proxy, install
from localstack.services.firehose import firehose_api
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.es import es_api
from localstack.services.generic_proxy import GenericProxy, SERVER_CERT_PEM_FILE

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False
# maps plugin scope ("services", "commands") to flags which indicate whether plugins have been loaded
PLUGINS_LOADED = {}
# flag to indicate whether we've received and processed the stop signal
INFRA_STOPPED = False

# default backend host address
DEFAULT_BACKEND_HOST = '127.0.0.1'

# set up logger
LOGGER = logging.getLogger(os.path.basename(__file__))

# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS = {}

# plugin scopes
PLUGIN_SCOPE_SERVICES = 'services'
PLUGIN_SCOPE_COMMANDS = 'commands'

# -----------------
# PLUGIN UTILITIES
# -----------------


class Plugin(object):
    def __init__(self, name, start, check=None, listener=None):
        self.plugin_name = name
        self.start_function = start
        self.listener = listener
        self.check_function = check

    def start(self, async):
        kwargs = {
            'async': async
        }
        if self.listener:
            kwargs['update_listener'] = self.listener
        return self.start_function(**kwargs)

    def check(self, expect_shutdown=False, print_error=False):
        if not self.check_function:
            return
        return self.check_function(expect_shutdown=expect_shutdown, print_error=print_error)

    def name(self):
        return self.plugin_name


def register_plugin(plugin):
    SERVICE_PLUGINS[plugin.name()] = plugin


def load_plugin_from_path(file_path, scope=None):
    if os.path.exists(file_path):
        module = re.sub(r'(^|.+/)([^/]+)/plugins.py', r'\2', file_path)
        method_name = 'register_localstack_plugins'
        scope = scope or PLUGIN_SCOPE_SERVICES
        if scope == PLUGIN_SCOPE_COMMANDS:
            method_name = 'register_localstack_commands'
        try:
            namespace = {}
            exec('from %s.plugins import %s' % (module, method_name), namespace)
            method_to_execute = namespace[method_name]
        except Exception as e:
            return
        try:
            return method_to_execute()
        except Exception as e:
            LOGGER.warning('Unable to load plugins from file %s: %s' % (file_path, e))


def load_plugins(scope=None):
    scope = scope or PLUGIN_SCOPE_SERVICES
    if PLUGINS_LOADED.get(scope, None):
        return
    logging.captureWarnings(True)
    logging.basicConfig(level=logging.WARNING)

    loaded_files = []
    result = []
    for module in pkgutil.iter_modules():
        file_path = None
        if six.PY3 and not isinstance(module, tuple):
            file_path = '%s/%s/plugins.py' % (module.module_finder.path, module.name)
        elif six.PY3 or isinstance(module[0], pkgutil.ImpImporter):
            if hasattr(module[0], 'path'):
                file_path = '%s/%s/plugins.py' % (module[0].path, module[1])
        if file_path and file_path not in loaded_files:
            plugin_config = load_plugin_from_path(file_path, scope=scope)
            if plugin_config:
                result.append(plugin_config)
            loaded_files.append(file_path)
    # set global flag
    PLUGINS_LOADED[scope] = result
    return result


# -----------------
# API ENTRY POINTS
# -----------------


def start_apigateway(port=PORT_APIGATEWAY, async=False, update_listener=None):
    return start_moto_server('apigateway', port, name='API Gateway', async=async,
        backend_port=DEFAULT_PORT_APIGATEWAY_BACKEND, update_listener=update_listener)


def start_s3(port=PORT_S3, async=False, update_listener=None):
    return start_moto_server('s3', port, name='S3', async=async,
        backend_port=DEFAULT_PORT_S3_BACKEND, update_listener=update_listener)


def start_sns(port=PORT_SNS, async=False, update_listener=None):
    return start_moto_server('sns', port, name='SNS', async=async,
        backend_port=DEFAULT_PORT_SNS_BACKEND, update_listener=update_listener)


def start_sqs(port=PORT_SQS, async=False, update_listener=None):
    return start_moto_server('sqs', port, name='SQS', async=async,
        backend_port=DEFAULT_PORT_SQS_BACKEND, update_listener=update_listener)


def start_cloudformation(port=PORT_CLOUDFORMATION, async=False, update_listener=None):
    return start_moto_server('cloudformation', port, name='CloudFormation', async=async,
        backend_port=DEFAULT_PORT_CLOUDFORMATION_BACKEND, update_listener=update_listener)


def start_cloudwatch(port=PORT_CLOUDWATCH, async=False):
    return start_moto_server('cloudwatch', port, name='CloudWatch', async=async)


def start_redshift(port=PORT_REDSHIFT, async=False):
    return start_moto_server('redshift', port, name='Redshift', async=async)


def start_route53(port=PORT_ROUTE53, async=False):
    return start_moto_server('route53', port, name='Route53', async=async)


def start_ses(port=PORT_SES, async=False):
    return start_moto_server('ses', port, name='SES', async=async)


def start_elasticsearch_service(port=PORT_ES, async=False):
    return start_local_api('ES', port, method=es_api.serve, async=async)


def start_firehose(port=PORT_FIREHOSE, async=False):
    return start_local_api('Firehose', port, method=firehose_api.serve, async=async)


def start_dynamodbstreams(port=PORT_DYNAMODBSTREAMS, async=False):
    return start_local_api('DynamoDB Streams', port, method=dynamodbstreams_api.serve, async=async)


def start_lambda(port=PORT_LAMBDA, async=False):
    return start_local_api('Lambda', port, method=lambda_api.serve, async=async)


# ---------------
# HELPER METHODS
# ---------------


def get_service_protocol():
    return 'https' if USE_SSL else 'http'


def restore_persisted_data(apis):
    for api in apis:
        persistence.restore_persisted_data(api)


def register_signal_handlers():
    global SIGNAL_HANDLERS_SETUP
    if SIGNAL_HANDLERS_SETUP:
        return

    # register signal handlers
    def signal_handler(signal, frame):
        stop_infra()
        os._exit(0)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    SIGNAL_HANDLERS_SETUP = True


def is_debug():
    return os.environ.get('DEBUG', '').strip() not in ['', '0', 'false']


def do_run(cmd, async, print_output=False):
    sys.stdout.flush()
    if async:
        if is_debug():
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(cmd, outfile=outfile)
        t.start()
        TMP_THREADS.append(t)
        return t
    else:
        return run(cmd)


def start_proxy(port, backend_port, update_listener, quiet=False,
        backend_host=DEFAULT_BACKEND_HOST, params={}):
    proxy_thread = GenericProxy(port=port, forward_host='%s:%s' % (backend_host, backend_port),
        ssl=USE_SSL, update_listener=update_listener, quiet=quiet, params=params)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)


def start_moto_server(key, port, name=None, backend_port=None, async=False, update_listener=None):
    cmd = 'VALIDATE_LAMBDA_S3=0 %s/bin/moto_server %s -p %s -H %s' % (LOCALSTACK_VENV_FOLDER, key,
        backend_port or port, constants.BIND_HOST)
    if not name:
        name = key
    print("Starting mock %s (%s port %s)..." % (name, get_service_protocol(), port))
    if backend_port:
        start_proxy(port, backend_port, update_listener)
    elif USE_SSL:
        cmd += ' --ssl'
    return do_run(cmd, async)


def start_local_api(name, port, method, async=False):
    print("Starting mock %s service (%s port %s)..." % (name, get_service_protocol(), port))
    if async:
        thread = FuncThread(method, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        method(port)


def stop_infra():
    global INFRA_STOPPED
    if INFRA_STOPPED:
        return

    event_publisher.fire_event(event_publisher.EVENT_STOP_INFRA)

    generic_proxy.QUIET = True
    common.cleanup(files=True, quiet=True)
    common.cleanup_resources()
    lambda_api.cleanup()
    time.sleep(2)
    # TODO: optimize this (takes too long currently)
    # check_infra(retries=2, expect_shutdown=True)
    INFRA_STOPPED = True


def check_aws_credentials():
    session = boto3.Session()
    credentials = session.get_credentials()
    if not credentials:
        # set temporary dummy credentials
        os.environ['AWS_ACCESS_KEY_ID'] = 'LocalStackDummyAccessKey'
        os.environ['AWS_SECRET_ACCESS_KEY'] = 'LocalStackDummySecretKey'
    session = boto3.Session()
    credentials = session.get_credentials()
    assert credentials


# -----------------------------
# INFRASTRUCTURE HEALTH CHECKS
# -----------------------------


def check_infra(retries=8, expect_shutdown=False, apis=None, additional_checks=[]):
    try:
        print_error = retries <= 0

        # loop through plugins and check service status
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                try:
                    plugin.check(expect_shutdown=expect_shutdown, print_error=print_error)
                except Exception as e:
                    LOGGER.warning('Service "%s" not yet available, retrying...' % name)
                    raise e

        for additional in additional_checks:
            additional(expect_shutdown=expect_shutdown)
    except Exception as e:
        if retries <= 0:
            LOGGER.error('Error checking state of local environment (after some retries): %s' % traceback.format_exc())
            raise e
        time.sleep(3)
        check_infra(retries - 1, expect_shutdown=expect_shutdown, apis=apis, additional_checks=additional_checks)


# -------------
# DOCKER STARTUP
# -------------


def start_infra_in_docker():
    # load plugins before starting the docker container
    plugin_configs = load_plugins()
    plugin_run_params = ' '.join([
        entry.get('docker', {}).get('run_flags', '') for entry in plugin_configs])

    services = os.environ.get('SERVICES', '')
    entrypoint = os.environ.get('ENTRYPOINT', '')
    cmd = os.environ.get('CMD', '')
    image_name = os.environ.get('IMAGE_NAME', constants.DOCKER_IMAGE_NAME)
    service_ports = config.SERVICE_PORTS

    # construct port mappings
    ports_list = sorted(service_ports.values())
    start_port = 0
    last_port = 0
    port_ranges = []
    for i in range(0, len(ports_list)):
        if not start_port:
            start_port = ports_list[i]
        if not last_port:
            last_port = ports_list[i]
        if ports_list[i] > last_port + 1:
            port_ranges.append([start_port, last_port])
            start_port = ports_list[i]
        elif i >= len(ports_list) - 1:
            port_ranges.append([start_port, ports_list[i]])
        last_port = ports_list[i]
    port_mappings = ' '.join(
        '-p {start}-{end}:{start}-{end}'.format(start=entry[0], end=entry[1])
        if entry[0] < entry[1] else '-p {port}:{port}'.format(port=entry[0])
        for entry in port_ranges)

    if services:
        port_mappings = ''
        for service, port in service_ports.items():
            port_mappings += ' -p {port}:{port}'.format(port=port)

    env_str = ''
    for env_var in config.CONFIG_ENV_VARS:
        value = os.environ.get(env_var, None)
        if value is not None:
            env_str += '-e %s="%s" ' % (env_var, value)

    data_dir_mount = ''
    data_dir = os.environ.get('DATA_DIR', None)
    if data_dir is not None:
        container_data_dir = '/tmp/localstack_data'
        data_dir_mount = '-v "%s:%s" ' % (data_dir, container_data_dir)
        env_str += '-e DATA_DIR="%s" ' % container_data_dir

    interactive = '-it ' if not in_ci() else ''

    # append space if parameter is set
    entrypoint = '%s ' % entrypoint if entrypoint else entrypoint
    plugin_run_params = '%s ' % plugin_run_params if plugin_run_params else plugin_run_params

    docker_cmd = ('docker run %s%s%s%s' +
        '-p 8080:8080 %s %s' +
        '-v "%s:/tmp/localstack" -v "%s:%s" ' +
        '-e DOCKER_HOST="unix://%s" ' +
        '-e HOST_TMP_FOLDER="%s" "%s" %s') % (
            interactive, entrypoint, env_str, plugin_run_params, port_mappings, data_dir_mount,
            config.TMP_FOLDER, config.DOCKER_SOCK, config.DOCKER_SOCK, config.DOCKER_SOCK,
            config.HOST_TMP_FOLDER, image_name, cmd
    )

    run('mkdir -p "{folder}"; chmod -R 777 "{folder}";'.format(folder=config.TMP_FOLDER))
    print(docker_cmd)
    t = ShellCommandThread(docker_cmd, outfile=subprocess.PIPE)
    t.start()
    time.sleep(2)
    t.process.wait()
    sys.exit(t.process.returncode)


# -------------
# MAIN STARTUP
# -------------


def start_infra(async=False, apis=None):
    try:
        # load plugins
        load_plugins()

        event_publisher.fire_event(event_publisher.EVENT_START_INFRA)

        # set up logging
        warnings.filterwarnings('ignore')
        logging.captureWarnings(True)
        logging.basicConfig(level=logging.WARNING)
        logging.getLogger('botocore').setLevel(logging.ERROR)
        logging.getLogger('elasticsearch').setLevel(logging.ERROR)
        LOGGER.setLevel(logging.INFO)

        if not apis:
            apis = list(config.SERVICE_PORTS.keys())
        # set environment
        os.environ['AWS_REGION'] = DEFAULT_REGION
        os.environ['ENV'] = ENV_DEV
        # register signal handlers
        register_signal_handlers()
        # make sure AWS credentials are configured, otherwise boto3 bails on us
        check_aws_credentials()
        # install libs if not present
        install.install_components(apis)
        # Some services take a bit to come up
        sleep_time = 3
        # start services
        thread = None

        if 'elasticsearch' in apis or 'es' in apis:
            sleep_time = max(sleep_time, 8)

        # loop through plugins and start each service
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                t1 = plugin.start(async=True)
                thread = thread or t1

        time.sleep(sleep_time)
        # check that all infra components are up and running
        check_infra(apis=apis)
        # restore persisted data
        restore_persisted_data(apis=apis)
        print('Ready.')
        sys.stdout.flush()
        if not async and thread:
            # this is a bit of an ugly hack, but we need to make sure that we
            # stay in the execution context of the main thread, otherwise our
            # signal handlers don't work
            while True:
                time.sleep(1)
        return thread
    except KeyboardInterrupt as e:
        print('Shutdown')
    except Exception as e:
        print('Error starting infrastructure: %s %s' % (e, traceback.format_exc()))
        sys.stdout.flush()
        raise e
    finally:
        if not async:
            stop_infra()
