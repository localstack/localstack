import os
import re
import sys
import json
import time
import signal
import logging
import traceback
import boto3
import subprocess
from requests.models import Response
from localstack import constants, config
from localstack.constants import (
    ENV_DEV, LOCALSTACK_VENV_FOLDER, ENV_INTERNAL_TEST_RUN, LOCALSTACK_INFRA_PROCESS, DEFAULT_SERVICE_PORTS)
from localstack.utils import common, persistence
from localstack.utils.common import (TMP_THREADS, run, get_free_tcp_port, is_linux,
    FuncThread, ShellCommandThread, get_service_protocol, in_docker, is_port_open, sleep_forever)
from localstack.utils.server import multiserver
from localstack.utils.bootstrap import (
    setup_logging, is_debug, canonicalize_api_names, load_plugins, in_ci)
from localstack.utils.analytics import event_publisher
from localstack.services import generic_proxy, install
from localstack.services.es import es_api
from localstack.services.plugins import SERVICE_PLUGINS, record_service_health, check_infra
from localstack.services.firehose import firehose_api
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import GenericProxy, GenericProxyHandler, ProxyListener
from localstack.services.dynamodbstreams import dynamodbstreams_api

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False

# default backend host address
DEFAULT_BACKEND_HOST = '127.0.0.1'

# set up logger
LOG = logging.getLogger(__name__)


# -----------------------
# CONFIG UPDATE BACKDOOR
# -----------------------

def update_config_variable(variable, new_value):
    if new_value is not None:
        LOG.info('Updating value of config variable "%s": %s' % (variable, new_value))
        setattr(config, variable, new_value)


class ConfigUpdateProxyListener(ProxyListener):
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
        update_config_variable(variable, new_value)
        value = getattr(config, variable, None)
        result = {'variable': variable, 'value': value}
        response._content = json.dumps(result)
        return response


GenericProxyHandler.DEFAULT_LISTENERS.append(ConfigUpdateProxyListener())


# -----------------
# API ENTRY POINTS
# -----------------

def start_sns(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SNS
    return start_moto_server('sns', port, name='SNS', asynchronous=asynchronous,
        update_listener=update_listener)


def start_cloudwatch(port=None, asynchronous=False):
    port = port or config.PORT_CLOUDWATCH
    return start_moto_server('cloudwatch', port, name='CloudWatch', asynchronous=asynchronous)


def start_sts(port=None, asynchronous=False):
    port = port or config.PORT_STS
    return start_moto_server('sts', port, name='STS', asynchronous=asynchronous)


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


def start_ssm(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_SSM
    return start_moto_server('ssm', port, name='SSM', asynchronous=asynchronous,
        update_listener=update_listener)


# ---------------
# HELPER METHODS
# ---------------

def patch_urllib3_connection_pool(**constructor_kwargs):
    """
    Override the default parameters of HTTPConnectionPool, e.g., set the pool size via maxsize=16
    """
    try:
        from urllib3 import connectionpool, poolmanager

        class MyHTTPSConnectionPool(connectionpool.HTTPSConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPSConnectionPool, self).__init__(*args, **kwargs)
        poolmanager.pool_classes_by_scheme['https'] = MyHTTPSConnectionPool

        class MyHTTPConnectionPool(connectionpool.HTTPConnectionPool):
            def __init__(self, *args, **kwargs):
                kwargs.update(constructor_kwargs)
                super(MyHTTPConnectionPool, self).__init__(*args, **kwargs)
        poolmanager.pool_classes_by_scheme['http'] = MyHTTPConnectionPool
    except Exception:
        pass


def set_service_status(data):
    command = data.get('command')
    service = data.get('service')
    service_ports = config.parse_service_ports()
    if command == 'start':
        existing = service_ports.get(service)
        port = DEFAULT_SERVICE_PORTS.get(service)
        if existing:
            status = get_service_status(service, port)
            if status == 'running':
                return
        key_upper = service.upper().replace('-', '_')
        port_variable = 'PORT_%s' % key_upper
        service_list = os.environ.get('SERVICES', '').strip()
        services = [e for e in re.split(r'[\s,]+', service_list) if e]
        contained = [s for s in services if s.startswith(service)]
        if not contained:
            services.append(service)
        update_config_variable(port_variable, port)
        new_service_list = ','.join(services)
        os.environ['SERVICES'] = new_service_list
        config.populate_configs()
        LOG.info('Starting service %s on port %s' % (service, port))
        SERVICE_PLUGINS[service].start(asynchronous=True)
    return {}


def get_services_status():
    result = {}
    for service, port in config.parse_service_ports().items():
        status = get_service_status(service, port)
        result[service] = {
            'port': port,
            'status': status
        }
    return result


def get_service_status(service, port=None):
    port = port or config.parse_service_ports().get(service)
    status = 'disabled' if (port or 0) <= 0 else 'running' if is_port_open(port) else 'stopped'
    return status


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


def do_run(cmd, asynchronous, print_output=None, env_vars={}):
    sys.stdout.flush()
    if asynchronous:
        if is_debug() and print_output is None:
            print_output = True
        outfile = subprocess.PIPE if print_output else None
        t = ShellCommandThread(cmd, outfile=outfile, env_vars=env_vars)
        t.start()
        TMP_THREADS.append(t)
        return t
    return run(cmd, env_vars=env_vars)


def start_proxy_for_service(service_name, port, backend_port, update_listener, quiet=False, params={}):
    # check if we have a custom backend configured
    custom_backend_url = os.environ.get('%s_BACKEND' % service_name.upper())
    backend_url = custom_backend_url or ('http://%s:%s' % (DEFAULT_BACKEND_HOST, backend_port))
    return start_proxy(port, backend_url=backend_url, update_listener=update_listener, quiet=quiet, params=params)


def start_proxy(port, backend_url, update_listener=None, quiet=False, params={}, use_ssl=None):
    use_ssl = config.USE_SSL if use_ssl is None else use_ssl
    proxy_thread = GenericProxy(port=port, forward_url=backend_url,
        ssl=use_ssl, update_listener=update_listener, quiet=quiet, params=params)
    proxy_thread.start()
    TMP_THREADS.append(proxy_thread)
    return proxy_thread


def start_moto_server(key, port, name=None, backend_port=None, asynchronous=False, update_listener=None):
    if not name:
        name = key
    print('Starting mock %s service in %s ports %s (recommended) and %s (deprecated)...' % (
        name, get_service_protocol(), config.EDGE_PORT, port))
    if not backend_port and (config.USE_SSL or update_listener):
        backend_port = get_free_tcp_port()
    if backend_port:
        start_proxy_for_service(key, port, backend_port, update_listener)
    if config.BUNDLE_API_PROCESSES:
        return multiserver.start_api_server(key, backend_port or port)
    return start_moto_server_separate(key, port, name=name, backend_port=backend_port, asynchronous=asynchronous)


def start_moto_server_separate(key, port, name=None, backend_port=None, asynchronous=False):
    moto_server_cmd = '%s/bin/moto_server' % LOCALSTACK_VENV_FOLDER
    if not os.path.exists(moto_server_cmd):
        moto_server_cmd = run('which moto_server').strip()
    cmd = 'VALIDATE_LAMBDA_S3=0 %s %s -p %s -H %s' % (moto_server_cmd, key, backend_port or port, constants.BIND_HOST)
    return do_run(cmd, asynchronous)


def start_local_api(name, port, method, asynchronous=False):
    print('Starting mock %s service in %s ports %s (recommended) and %s (deprecated)...' % (
        name, get_service_protocol(), config.EDGE_PORT, port))
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


# -------------
# MAIN STARTUP
# -------------


def start_infra(asynchronous=False, apis=None):
    try:
        os.environ[LOCALSTACK_INFRA_PROCESS] = '1'

        is_in_docker = in_docker()
        # print a warning if we're not running in Docker but using Docker based LAMBDA_EXECUTOR
        if not is_in_docker and 'docker' in config.LAMBDA_EXECUTOR and not is_linux():
            print(('!WARNING! - Running outside of Docker with $LAMBDA_EXECUTOR=%s can lead to '
                   'problems on your OS. The environment variable $LOCALSTACK_HOSTNAME may not '
                   'be properly set in your Lambdas.') % config.LAMBDA_EXECUTOR)

        if is_in_docker and config.LAMBDA_REMOTE_DOCKER and not os.environ.get('HOST_TMP_FOLDER'):
            print('!WARNING! - Looks like you have configured $LAMBDA_REMOTE_DOCKER=1 - '
                  "please make sure to configure $HOST_TMP_FOLDER to point to your host's $TMPDIR")

        # apply patches
        patch_urllib3_connection_pool(maxsize=128)

        # load plugins
        load_plugins()

        # with plugins loaded, now start the infrastructure
        do_start_infra(asynchronous, apis, is_in_docker)

    except KeyboardInterrupt:
        print('Shutdown')
    except Exception as e:
        print('Error starting infrastructure: %s %s' % (e, traceback.format_exc()))
        sys.stdout.flush()
        raise e
    finally:
        if not asynchronous:
            stop_infra()


def do_start_infra(asynchronous, apis, is_in_docker):
    event_publisher.fire_event(event_publisher.EVENT_START_INFRA,
        {'d': is_in_docker and 1 or 0, 'c': in_ci() and 1 or 0})

    # set up logging
    setup_logging()

    # prepare APIs
    apis = canonicalize_api_names(apis)
    # set environment
    os.environ['AWS_REGION'] = config.DEFAULT_REGION
    os.environ['ENV'] = ENV_DEV
    # register signal handlers
    if not os.environ.get(ENV_INTERNAL_TEST_RUN):
        register_signal_handlers()
    # make sure AWS credentials are configured, otherwise boto3 bails on us
    check_aws_credentials()
    # install libs if not present
    install.install_components(apis)
    # Some services take a bit to come up
    sleep_time = 5
    # start services
    thread = None

    # loop through plugins and start each service
    for name, plugin in SERVICE_PLUGINS.items():
        if plugin.is_enabled(api_names=apis):
            record_service_health(name, 'starting')
            t1 = plugin.start(asynchronous=True)
            thread = thread or t1

    time.sleep(sleep_time)
    # ensure that all infra components are up and running
    check_infra(apis=apis)
    # restore persisted data
    persistence.restore_persisted_data(apis=apis)
    print('Ready.')
    sys.stdout.flush()
    if not asynchronous and thread:
        # this is a bit of an ugly hack, but we need to make sure that we
        # stay in the execution context of the main thread, otherwise our
        # signal handlers don't work
        sleep_forever()
    return thread
