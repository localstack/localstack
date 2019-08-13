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
from requests.models import Response
from localstack import constants, config
from localstack.config import USE_SSL
from localstack.constants import (
    ENV_DEV, DEFAULT_REGION, LOCALSTACK_VENV_FOLDER, ENV_INTERNAL_TEST_RUN,
    DEFAULT_PORT_APIGATEWAY_BACKEND, DEFAULT_PORT_SNS_BACKEND, DEFAULT_PORT_IAM_BACKEND)
from localstack.utils import common, persistence
from localstack.utils.common import (TMP_THREADS, run, get_free_tcp_port,
    FuncThread, ShellCommandThread, get_service_protocol, in_docker)
from localstack.utils.server import multiserver
from localstack.utils.bootstrap import setup_logging, is_debug, canonicalize_api_names
from localstack.utils.analytics import event_publisher
from localstack.utils.bootstrap import load_plugins
from localstack.services import generic_proxy, install
from localstack.services.es import es_api
from localstack.services.firehose import firehose_api
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import GenericProxy, GenericProxyHandler
from localstack.services.dynamodbstreams import dynamodbstreams_api

# flag to indicate whether signal handlers have been set up already
SIGNAL_HANDLERS_SETUP = False

# default backend host address
DEFAULT_BACKEND_HOST = '127.0.0.1'

# set up logger
LOG = logging.getLogger(os.path.basename(__file__))

# map of service plugins, mapping from service name to plugin details
SERVICE_PLUGINS = {}


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


def start_events(port=None, asynchronous=False):
    port = port or config.PORT_EVENTS
    return start_moto_server('events', port, name='CloudWatch Events', asynchronous=asynchronous)


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
    if not name:
        name = key
    print('Starting mock %s (%s port %s)...' % (name, get_service_protocol(), port))
    if USE_SSL and not backend_port:
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
# MAIN STARTUP
# -------------


def start_infra(asynchronous=False, apis=None):
    try:
        # load plugins
        load_plugins()

        event_publisher.fire_event(event_publisher.EVENT_START_INFRA, {'d': in_docker() and 1 or 0})

        # set up logging
        setup_logging()

        # prepare APIs
        apis = canonicalize_api_names(apis)
        # set environment
        os.environ['AWS_REGION'] = DEFAULT_REGION
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

        if 'elasticsearch' in apis or 'es' in apis:
            sleep_time = max(sleep_time, 10)

        # loop through plugins and start each service
        for name, plugin in SERVICE_PLUGINS.items():
            if name in apis:
                t1 = plugin.start(asynchronous=True)
                thread = thread or t1

        time.sleep(sleep_time)
        # ensure that all infra components are up and running
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
