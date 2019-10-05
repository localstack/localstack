import re
import os
import socket
import logging
import platform
import tempfile
import subprocess
from os.path import expanduser
import six
from boto3 import Session
from localstack.constants import (
    DEFAULT_SERVICE_PORTS, LOCALHOST, PATH_USER_REQUEST, DEFAULT_PORT_WEB_UI, TRUE_STRINGS, FALSE_STRINGS)

TRUE_VALUES = ('1', 'true')

# java options to Lambda
LAMBDA_JAVA_OPTS = os.environ.get('LAMBDA_JAVA_OPTS', '').strip()

# limit in which to kinesalite will start throwing exceptions
KINESIS_SHARD_LIMIT = os.environ.get('KINESIS_SHARD_LIMIT', '').strip() or '100'

# delay in kinesalite response when making changes to streams
KINESIS_LATENCY = os.environ.get('KINESIS_LATENCY', '').strip() or '500'

# default AWS region
if 'DEFAULT_REGION' not in os.environ:
    os.environ['DEFAULT_REGION'] = 'us-east-1'
DEFAULT_REGION = os.environ['DEFAULT_REGION']

# randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = float(os.environ.get('KINESIS_ERROR_PROBABILITY', '').strip() or 0.0)

# randomly inject faults to DynamoDB
DYNAMODB_ERROR_PROBABILITY = float(os.environ.get('DYNAMODB_ERROR_PROBABILITY', '').strip() or 0.0)

# expose services on a specific host internally
HOSTNAME = os.environ.get('HOSTNAME', '').strip() or LOCALHOST

# expose services on a specific host externally
HOSTNAME_EXTERNAL = os.environ.get('HOSTNAME_EXTERNAL', '').strip() or LOCALHOST

# expose SQS on a specific port externally
SQS_PORT_EXTERNAL = int(os.environ.get('SQS_PORT_EXTERNAL') or 0)

# name of the host under which the LocalStack services are available
LOCALSTACK_HOSTNAME = os.environ.get('LOCALSTACK_HOSTNAME', '').strip() or HOSTNAME

# whether to remotely copy the lambda or locally mount a volume
LAMBDA_REMOTE_DOCKER = os.environ.get('LAMBDA_REMOTE_DOCKER', '').lower().strip() in TRUE_VALUES

# network that the docker lambda container will be joining
LAMBDA_DOCKER_NETWORK = os.environ.get('LAMBDA_DOCKER_NETWORK', '').strip()

# directory for persisting data
DATA_DIR = os.environ.get('DATA_DIR', '').strip()

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), 'localstack')

# create folders
for folder in [DATA_DIR, TMP_FOLDER]:
    if folder and not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except Exception:
            # this can happen due to a race condition when starting
            # multiple processes in parallel. Should be safe to ignore
            pass

# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith('/var/folders/') and os.path.exists('/private%s' % TMP_FOLDER):
    TMP_FOLDER = '/private%s' % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set
HOST_TMP_FOLDER = os.environ.get('HOST_TMP_FOLDER', TMP_FOLDER)

# whether to use SSL encryption for the services
USE_SSL = os.environ.get('USE_SSL', '').strip() in TRUE_STRINGS

# default encoding used to convert strings to byte arrays (mainly for Python 3 compatibility)
DEFAULT_ENCODING = 'utf-8'

# path to local Docker UNIX domain socket
DOCKER_SOCK = os.environ.get('DOCKER_SOCK', '').strip() or '/var/run/docker.sock'

# additional flags to pass to "docker run" when starting the stack in Docker
DOCKER_FLAGS = os.environ.get('DOCKER_FLAGS', '').strip()

# command used to run Docker containers (e.g., set to "sudo docker" to run as sudo)
DOCKER_CMD = os.environ.get('DOCKER_CMD', '').strip() or 'docker'

# whether to start the web API
START_WEB = os.environ.get('START_WEB', '').strip() not in FALSE_STRINGS

# port of Web UI
PORT_WEB_UI = int(os.environ.get('PORT_WEB_UI', '').strip() or DEFAULT_PORT_WEB_UI)
PORT_WEB_UI_SSL = PORT_WEB_UI + 1

# IP of the docker bridge used to enable access between containers
DOCKER_BRIDGE_IP = os.environ.get('DOCKER_BRIDGE_IP', '').strip()

# CORS settings
EXTRA_CORS_ALLOWED_HEADERS = os.environ.get('EXTRA_CORS_ALLOWED_HEADERS', '').strip()
EXTRA_CORS_EXPOSE_HEADERS = os.environ.get('EXTRA_CORS_EXPOSE_HEADERS', '').strip()


def has_docker():
    try:
        with open(os.devnull, 'w') as devnull:
            subprocess.check_output('docker ps', stderr=devnull, shell=True)
        return True
    except Exception:
        return False


def is_linux():
    try:
        out = subprocess.check_output('uname -a', shell=True)
        out = out.decode('utf-8') if isinstance(out, six.binary_type) else out
        return 'Linux' in out
    except subprocess.CalledProcessError:
        return False


# whether to use Lambda functions in a Docker container
LAMBDA_EXECUTOR = os.environ.get('LAMBDA_EXECUTOR', '').strip()
if not LAMBDA_EXECUTOR:
    LAMBDA_EXECUTOR = 'docker'
    if not has_docker():
        LAMBDA_EXECUTOR = 'local'

# Fallback URL to use when a non-existing Lambda is invoked. If this matches
# `dynamodb://<table_name>`, then the invocation is recorded in the corresponding
# DynamoDB table. If this matches `http(s)://...`, then the Lambda invocation is
# forwarded as a POST request to that URL.
LAMBDA_FALLBACK_URL = os.environ.get('LAMBDA_FALLBACK_URL', '').strip()

# list of environment variable names used for configuration.
# Make sure to keep this in sync with the above!
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = ['SERVICES', 'HOSTNAME', 'HOSTNAME_EXTERNAL', 'LOCALSTACK_HOSTNAME', 'LAMBDA_FALLBACK_URL',
                   'LAMBDA_EXECUTOR', 'LAMBDA_REMOTE_DOCKER', 'LAMBDA_DOCKER_NETWORK', 'USE_SSL', 'DEBUG',
                   'KINESIS_ERROR_PROBABILITY', 'DYNAMODB_ERROR_PROBABILITY', 'PORT_WEB_UI', 'START_WEB',
                   'DOCKER_BRIDGE_IP', 'DEFAULT_REGION', 'LAMBDA_JAVA_OPTS', 'LOCALSTACK_API_KEY']

for key, value in six.iteritems(DEFAULT_SERVICE_PORTS):
    clean_key = key.upper().replace('-', '_')
    CONFIG_ENV_VARS += [clean_key + '_BACKEND', clean_key + '_PORT', clean_key + '_PORT_EXTERNAL']

# create variable aliases prefixed with LOCALSTACK_ (except LOCALSTACK_HOSTNAME)
CONFIG_ENV_VARS += ['LOCALSTACK_' + v for v in CONFIG_ENV_VARS]


def ping(host):
    """ Returns True if host responds to a ping request """
    is_windows = platform.system().lower() == 'windows'
    ping_opts = '-n 1' if is_windows else '-c 1'
    args = 'ping %s %s' % (ping_opts, host)
    return subprocess.call(args, shell=not is_windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0


def in_docker():
    """ Returns True if running in a docker container, else False """
    if not os.path.exists('/proc/1/cgroup'):
        return False
    with open('/proc/1/cgroup', 'rt') as ifh:
        return 'docker' in ifh.read()


is_in_docker = in_docker()

# determine IP of Docker bridge
if not DOCKER_BRIDGE_IP:
    DOCKER_BRIDGE_IP = '172.17.0.1'
    if is_in_docker:
        candidates = (DOCKER_BRIDGE_IP, '172.18.0.1')
        for ip in candidates:
            if ping(ip):
                DOCKER_BRIDGE_IP = ip
                break

# determine route to Docker host from container
try:
    DOCKER_HOST_FROM_CONTAINER = DOCKER_BRIDGE_IP
    if not is_in_docker:
        DOCKER_HOST_FROM_CONTAINER = socket.gethostbyname('host.docker.internal')
    # update LOCALSTACK_HOSTNAME if host.docker.internal is available
    if is_in_docker and LOCALSTACK_HOSTNAME == DOCKER_BRIDGE_IP:
        LOCALSTACK_HOSTNAME = DOCKER_HOST_FROM_CONTAINER
except socket.error:
    pass

# make sure we default to LAMBDA_REMOTE_DOCKER=true if running in Docker
if is_in_docker and not os.environ.get('LAMBDA_REMOTE_DOCKER', '').strip():
    LAMBDA_REMOTE_DOCKER = True

# local config file path in home directory
CONFIG_FILE_PATH = os.path.join(expanduser('~'), '.localstack')

# set variables no_proxy, i.e., run internal service calls directly
no_proxy = ','.join(set((LOCALSTACK_HOSTNAME, HOSTNAME, LOCALHOST, '127.0.0.1', '[::1]')))
if os.environ.get('no_proxy'):
    os.environ['no_proxy'] += ',' + no_proxy
elif os.environ.get('NO_PROXY'):
    os.environ['NO_PROXY'] += ',' + no_proxy
else:
    os.environ['no_proxy'] = no_proxy

# additional CLI commands, can be set by plugins
CLI_COMMANDS = {}

# set of valid regions
VALID_REGIONS = set(Session().get_available_regions('sns'))


def parse_service_ports():
    """ Parses the environment variable $SERVICES with a comma-separated list of services
        and (optional) ports they should run on: 'service1:port1,service2,service3:port3' """
    service_ports = os.environ.get('SERVICES', '').strip()
    if not service_ports:
        return DEFAULT_SERVICE_PORTS
    result = {}
    for service_port in re.split(r'\s*,\s*', service_ports):
        parts = re.split(r'[:=]', service_port)
        service = parts[0]
        key_upper = service.upper().replace('-', '_')
        port_env_name = '%s_PORT' % key_upper
        # (1) set default port number
        port_number = DEFAULT_SERVICE_PORTS.get(service)
        # (2) set port number from <SERVICE>_PORT environment, if present
        if os.environ.get(port_env_name):
            port_number = os.environ.get(port_env_name)
        # (3) set port number from <service>:<port> portion in $SERVICES, if present
        if len(parts) > 1:
            port_number = int(parts[-1])
        # (4) try to parse as int, fall back to 0 (invalid port)
        try:
            port_number = int(port_number)
        except Exception:
            port_number = 0
        result[service] = port_number
    return result


def populate_configs(service_ports=None):
    global SERVICE_PORTS

    SERVICE_PORTS = service_ports or parse_service_ports()
    globs = globals()

    # define service ports and URLs as environment variables
    for key, value in six.iteritems(DEFAULT_SERVICE_PORTS):
        key_upper = key.upper().replace('-', '_')

        # define PORT_* variables with actual service ports as per configuration
        port_var_name = 'PORT_%s' % key_upper
        port_number = SERVICE_PORTS.get(key, 0)
        globs[port_var_name] = port_number
        url = 'http%s://%s:%s' % ('s' if USE_SSL else '', LOCALSTACK_HOSTNAME, port_number)
        # define TEST_*_URL variables with mock service endpoints
        url_key = 'TEST_%s_URL' % key_upper
        globs[url_key] = url
        # expose HOST_*_URL variables as environment variables
        os.environ[url_key] = url

    # expose LOCALSTACK_HOSTNAME as env. variable
    os.environ['LOCALSTACK_HOSTNAME'] = LOCALSTACK_HOSTNAME


def service_port(service_key):
    return SERVICE_PORTS.get(service_key, 0)


# initialize config values
populate_configs()

# set log level
if os.environ.get('DEBUG', '').lower() in TRUE_VALUES:
    logging.getLogger('').setLevel(logging.DEBUG)
    logging.getLogger('localstack').setLevel(logging.DEBUG)

# whether to bundle multiple APIs into a single process, where possible
BUNDLE_API_PROCESSES = True

# whether to use a CPU/memory profiler when running the integration tests
USE_PROFILER = os.environ.get('USE_PROFILER', '').lower() in TRUE_VALUES

# set URL pattern of inbound API gateway
INBOUND_GATEWAY_URL_PATTERN = ('%s/restapis/{api_id}/{stage_name}/%s{path}' %
                               (TEST_APIGATEWAY_URL, PATH_USER_REQUEST))  # noqa
