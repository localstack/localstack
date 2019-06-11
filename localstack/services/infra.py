import os
import re
import sys
import json
import time
import signal
import traceback
import logging
import boto3
import subprocess
import six
import warnings
import pkgutil
from requests.models import Response
from localstack import constants, config
from localstack.constants import (
    ENV_DEV, DEFAULT_REGION, LOCALSTACK_VENV_FOLDER,
    DEFAULT_PORT_APIGATEWAY_BACKEND, DEFAULT_PORT_SNS_BACKEND, DEFAULT_PORT_IAM_BACKEND)
from localstack.config import USE_SSL
from localstack.utils import common, persistence
from localstack.utils.common import (run, TMP_THREADS, in_ci, run_cmd_safe, get_free_tcp_port,
    TIMESTAMP_FORMAT, FuncThread, ShellCommandThread, mkdir, get_service_protocol, docker_container_running)
from localstack.utils.analytics import event_publisher
from localstack.services import generic_proxy, install
from localstack.services.es import es_api
from localstack.services.firehose import firehose_api
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import GenericProxy, GenericProxyHandler
from localstack.services.dynamodbstreams import dynamodbstreams_api

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False

# maps plugin scope ("services", "commands") to flags which indicate whether plugins have been loaded
PLUGINS_LOADED = {}

# maps from API names to list of other API names that they depend on
API_DEPENDENCIES = {
    'dynamodbstreams': ['kinesis'],
    'lambda': ['logs'],
    'es': ['elasticsearch']
}
# composites define an abstract name like "serverless" that maps to a set of services
API_COMPOSITES = {
    'serverless': ['iam', 'lambda', 'dynamodb', 'apigateway', 's3', 'sns']
}

# default backend host address
DEFAULT_BACKEND_HOST = '127.0.0.1'

# set up logger
LOG = logging.getLogger(os.path.basename(__file__))

# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS = {}

# whether or not to manually fix permissions on /var/run/docker.sock (currently disabled)
DO_CHMOD_DOCKER_SOCK = False

# plugin scopes
PLUGIN_SCOPE_SERVICES = 'services'
PLUGIN_SCOPE_COMMANDS = 'commands'

# log format strings
LOG_FORMAT = '%(asctime)s:%(levelname)s:%(name)s: %(message)s'
LOG_DATE_FORMAT = TIMESTAMP_FORMAT


# -----------------
# PLUGIN UTILITIES
# -----------------


class Plugin(object):

    def __init__(self, name, start, check=None, listener=None):
        self.plugin_name = name
        self.start_function = start
        self.listener = listener
        self.check_function = check

    def start(self, asynchronous):
        kwargs = {
            'asynchronous': asynchronous
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
            if not re.match(r'.*cannot import name .*%s.*' % method_name, str(e)):
                LOG.debug('Unable to load plugins from module %s: %s' % (module, e))
            return
        try:
            return method_to_execute()
        except Exception as e:
            LOG.warning('Unable to load plugins from file %s: %s' % (file_path, e))


def load_plugins(scope=None):
    scope = scope or PLUGIN_SCOPE_SERVICES
    if PLUGINS_LOADED.get(scope):
        return PLUGINS_LOADED[scope]

    setup_logging()

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


# -----------------------
# CONFIG UPDATE BACKDOOR
# -----------------------


class ConfigUpdateProxyListener(object):
    """ Default proxy listener that intercepts requests to retrieve or update config variables. """

    def forward_request(self, method, path, data, headers):
        if path != constants.CONFIG_UPDATE_PATH or method != 'POST':
            return True
        response = Response()
        data = json.loads(data)
        variable = data.get('variable', '')
        response._content = '{}'
        response.status_code = 200
        if not re.match(r'^[_a-zA-Z0-9]+$', variable):
            response.status_code = 400
            return response
        new_value = data.get('value')
        if new_value is not None:
            LOG.info('Updating value of config variable "%s": %s' % (variable, new_value))
            setattr(config, variable, new_value)
        value = getattr(config, variable, None)
        result = {'variable': variable, 'value': value}
        response._content = json.dumps(result)
        return response


GenericProxyHandler.DEFAULT_LISTENERS.append(ConfigUpdateProxyListener())


# -----------------
# API ENTRY POINTS
# -----------------


def start_apigateway(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    return start_moto_server('apigateway', port, name='API Gateway', asynchronous=asynchronous,
        backend_port=DEFAULT_PORT_APIGATEWAY_BACKEND, update_listener=update_listener)


def start_sns(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SNS
    return start_moto_server('sns', port, name='SNS', asynchronous=asynchronous,
        backend_port=DEFAULT_PORT_SNS_BACKEND, update_listener=update_listener)


def start_cloudwatch(port=None, asynchronous=False):
    port = port or config.PORT_CLOUDWATCH
    return start_moto_server('cloudwatch', port, name='CloudWatch', asynchronous=asynchronous)


def start_cloudwatch_logs(port=None, asynchronous=False):
    port = port or config.PORT_LOGS
    return start_moto_server('logs', port, name='CloudWatch Logs', asynchronous=asynchronous)


def start_sts(port=None, asynchronous=False):
    port = port or config.PORT_STS
    return start_moto_server('sts', port, name='STS', asynchronous=asynchronous)


def start_iam(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_IAM
    return start_moto_server('iam', port, name='IAM', asynchronous=asynchronous,
        backend_port=DEFAULT_PORT_IAM_BACKEND, update_listener=update_listener)


def start_redshift(port=None, asynchronous=False):
    port = port or config.PORT_REDSHIFT
    return start_moto_server('redshift', port, name='Redshift', asynchronous=asynchronous)


def start_route53(port=None, asynchronous=False):
    port = port or config.PORT_ROUTE53
    return start_moto_server('route53', port, name='Route53', asynchronous=asynchronous)


def start_ses(port=None, asynchronous=False):
    port = port or config.PORT_SES
    return start_moto_server('ses', port, name='SES', asynchronous=asynchronous)


def start_elasticsearch_service(port=None, asynchronous=False):
    port = port or config.PORT_ES
    return start_local_api('ES', port, method=es_api.serve, asynchronous=asynchronous)


def start_firehose(port=None, asynchronous=False):
    port = port or config.PORT_FIREHOSE
    return start_local_api('Firehose', port, method=firehose_api.serve, asynchronous=asynchronous)


def start_dynamodbstreams(port=None, asynchronous=False):
    port = port or config.PORT_DYNAMODBSTREAMS
    return start_local_api('DynamoDB Streams', port, method=dynamodbstreams_api.serve, asynchronous=asynchronous)


def start_lambda(port=None, asynchronous=False):
    port = port or config.PORT_LAMBDA
    return start_local_api('Lambda', port, method=lambda_api.serve, asynchronous=asynchronous)


def start_ssm(port=None, asynchronous=False):
    port = port or config.PORT_SSM
    return start_moto_server('ssm', port, name='SSM', asynchronous=asynchronous)


def start_secretsmanager(port=None, asynchronous=False):
    port = port or config.PORT_SECRETSMANAGER
    return start_moto_server('secretsmanager', port, name='Secrets Manager', asynchronous=asynchronous)


def start_ec2(port=None, asynchronous=False):
    port = port or config.PORT_EC2
    return start_moto_server('ec2', port, name='EC2', asynchronous=asynchronous)


# ---------------
# HELPER METHODS
# ---------------

def setup_logging():
    # determine and set log level
    log_level = logging.DEBUG if is_debug() else logging.INFO
    logging.basicConfig(level=log_level, format=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    # disable some logs and warnings
    warnings.filterwarnings('ignore')
    logging.captureWarnings(True)
    logging.getLogger('boto3').setLevel(logging.INFO)
    logging.getLogger('s3transfer').setLevel(logging.INFO)
    logging.getLogger('docker').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('botocore').setLevel(logging.ERROR)
    logging.getLogger('elasticsearch').setLevel(logging.ERROR)


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


def do_run(cmd, asynchronous, print_output=False, env_vars={}):
    sys.stdout.flush()
    if asynchronous:
        if is_debug():
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(cmd, outfile=outfile, env_vars=env_vars)
        t.start()
        TMP_THREADS.append(t)
        return t
    else:
        return run(cmd)


def start_proxy_for_service(service_name, port, default_backend_port, update_listener, quiet=False, params={}):
    # check if we have a custom backend configured
    custom_backend_url = os.environ.get('%s_BACKEND' % service_name.upper())
    backend_url = custom_backend_url or ('http://%s:%s' % (DEFAULT_BACKEND_HOST, default_backend_port))
    return start_proxy(port, backend_url=backend_url, update_listener=update_listener, quiet=quiet, params=params)


def start_proxy(port, backend_url, update_listener, quiet=False, params={}):
    proxy_thread = GenericProxy(port=port, forward_url=backend_url,
        ssl=USE_SSL, update_listener=update_listener, quiet=quiet, params=params)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)
    return proxy_thread


def start_moto_server(key, port, name=None, backend_port=None, asynchronous=False, update_listener=None):
    moto_server_cmd = '%s/bin/moto_server' % LOCALSTACK_VENV_FOLDER
    if not os.path.exists(moto_server_cmd):
        moto_server_cmd = run('which moto_server').strip()
    if USE_SSL and not backend_port:
        backend_port = get_free_tcp_port()
    cmd = 'VALIDATE_LAMBDA_S3=0 %s %s -p %s -H %s' % (moto_server_cmd, key, backend_port or port, constants.BIND_HOST)
    if not name:
        name = key
    print('Starting mock %s (%s port %s)...' % (name, get_service_protocol(), port))
    if backend_port:
        start_proxy_for_service(key, port, backend_port, update_listener)
    return do_run(cmd, asynchronous)


def start_local_api(name, port, method, asynchronous=False):
    print('Starting mock %s service (%s port %s)...' % (name, get_service_protocol(), port))
    if asynchronous:
        thread = FuncThread(method, port, quiet=True)
        thread.start()
        TMP_THREADS.append(thread)
        return thread
    else:
        method(port)


def stop_infra():
    if common.INFRA_STOPPED:
        return
    common.INFRA_STOPPED = True

    event_publisher.fire_event(event_publisher.EVENT_STOP_INFRA)

    generic_proxy.QUIET = True
    common.cleanup(files=True, quiet=True)
    common.cleanup_resources()
    lambda_api.cleanup()
    time.sleep(2)
    # TODO: optimize this (takes too long currently)
    # check_infra(retries=2, expect_shutdown=True)


def check_aws_credentials():
    session = boto3.Session()
    credentials = None
    try:
        credentials = session.get_credentials()
    except Exception:
        pass
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


def check_infra(retries=10, expect_shutdown=False, apis=None, additional_checks=[]):
    try:
        print_error = retries <= 0

        # loop through plugins and check service status
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                try:
                    plugin.check(expect_shutdown=expect_shutdown, print_error=print_error)
                except Exception as e:
                    LOG.warning('Service "%s" not yet available, retrying...' % name)
                    raise e

        for additional in additional_checks:
            additional(expect_shutdown=expect_shutdown)
    except Exception as e:
        if retries <= 0:
            LOG.error('Error checking state of local environment (after some retries): %s' % traceback.format_exc())
            raise e
        time.sleep(3)
        check_infra(retries - 1, expect_shutdown=expect_shutdown, apis=apis, additional_checks=additional_checks)


# -------------
# DOCKER STARTUP
# -------------


def start_infra_in_docker():

    container_name = 'localstack_main'

    if docker_container_running(container_name):
        raise Exception('LocalStack container named "%s" is already running' % container_name)

    # load plugins before starting the docker container
    plugin_configs = load_plugins()
    plugin_run_params = ' '.join([
        entry.get('docker', {}).get('run_flags', '') for entry in plugin_configs])

    # prepare APIs
    canonicalize_api_names()

    services = os.environ.get('SERVICES', '')
    entrypoint = os.environ.get('ENTRYPOINT', '')
    cmd = os.environ.get('CMD', '')
    user_flags = os.environ.get('DOCKER_FLAGS', '')
    image_name = os.environ.get('IMAGE_NAME', constants.DOCKER_IMAGE_NAME)
    service_ports = config.SERVICE_PORTS
    force_noninteractive = os.environ.get('FORCE_NONINTERACTIVE', '')

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

    interactive = '' if force_noninteractive or in_ci() else '-it '

    # append space if parameter is set
    user_flags = '%s ' % user_flags if user_flags else user_flags
    entrypoint = '%s ' % entrypoint if entrypoint else entrypoint
    plugin_run_params = '%s ' % plugin_run_params if plugin_run_params else plugin_run_params

    container_name = 'localstack_main'

    docker_cmd = ('docker run %s%s%s%s%s' +
        '--rm --privileged ' +
        '--name %s ' +
        '-p 8080:8080 %s %s' +
        '-v "%s:/tmp/localstack" -v "%s:%s" ' +
        '-e DOCKER_HOST="unix://%s" ' +
        '-e HOST_TMP_FOLDER="%s" "%s" %s') % (
            interactive, entrypoint, env_str, user_flags, plugin_run_params, container_name, port_mappings,
            data_dir_mount, config.TMP_FOLDER, config.DOCKER_SOCK, config.DOCKER_SOCK, config.DOCKER_SOCK,
            config.HOST_TMP_FOLDER, image_name, cmd
    )

    mkdir(config.TMP_FOLDER)
    run_cmd_safe(cmd='chmod -R 777 "%s"' % config.TMP_FOLDER)

    print(docker_cmd)
    t = ShellCommandThread(docker_cmd, outfile=subprocess.PIPE)
    t.start()
    time.sleep(2)

    if DO_CHMOD_DOCKER_SOCK:
        # fix permissions on /var/run/docker.sock
        for i in range(0, 100):
            if docker_container_running(container_name):
                break
            time.sleep(2)
        run('docker exec -u root "%s" chmod 777 /var/run/docker.sock' % container_name)

    t.process.wait()
    sys.exit(t.process.returncode)


# -------------
# MAIN STARTUP
# -------------


def canonicalize_api_names(apis=None):
    """ Finalize the list of API names by
        (1) resolving and adding dependencies (e.g., "dynamodbstreams" requires "kinesis"),
        (2) resolving and adding composites (e.g., "serverless" describes an ensemble
                including "iam", "lambda", "dynamodb", "apigateway", "s3", "sns", and "logs"), and
        (3) removing duplicates from the list. """

    apis = apis or list(config.SERVICE_PORTS.keys())

    def contains(apis, api):
        for a in apis:
            if a == api:
                return True

    # resolve composites
    for comp, deps in API_COMPOSITES.items():
        if contains(apis, comp):
            apis.extend(deps)
            config.SERVICE_PORTS.pop(comp)

    # resolve dependencies
    for i, api in enumerate(apis):
        for dep in API_DEPENDENCIES.get(api, []):
            if not contains(apis, dep):
                apis.append(dep)

    # remove duplicates and composite names
    apis = list(set([a for a in apis if a not in API_COMPOSITES.keys()]))

    # make sure we have port mappings for each API
    for api in apis:
        if api not in config.SERVICE_PORTS:
            config.SERVICE_PORTS[api] = config.DEFAULT_SERVICE_PORTS.get(api)
    config.populate_configs(config.SERVICE_PORTS)

    return apis


def start_infra(asynchronous=False, apis=None):
    try:
        # load plugins
        load_plugins()

        event_publisher.fire_event(event_publisher.EVENT_START_INFRA)

        # set up logging
        setup_logging()

        # prepare APIs
        apis = canonicalize_api_names(apis)
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
        sleep_time = 5
        # start services
        thread = None

        if 'elasticsearch' in apis or 'es' in apis:
            sleep_time = max(sleep_time, 10)

        # loop through plugins and start each service
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                t1 = plugin.start(asynchronous=True)
                thread = thread or t1

        time.sleep(sleep_time)
        # check that all infra components are up and running
        check_infra(apis=apis)
        # restore persisted data
        restore_persisted_data(apis=apis)
        print('Ready.')
        sys.stdout.flush()
        if not asynchronous and thread:
            # this is a bit of an ugly hack, but we need to make sure that we
            # stay in the execution context of the main thread, otherwise our
            # signal handlers don't work
            while True:
                time.sleep(1)
        return thread
    except KeyboardInterrupt:
        print('Shutdown')
    except Exception as e:
        print('Error starting infrastructure: %s %s' % (e, traceback.format_exc()))
        sys.stdout.flush()
        raise e
    finally:
        if not asynchronous:
            stop_infra()
