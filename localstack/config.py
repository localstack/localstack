import re
import os
import socket
import subprocess
import tempfile
import logging
from os.path import expanduser
from six import iteritems
from boto3 import Session
from localstack.constants import DEFAULT_SERVICE_PORTS, LOCALHOST, PATH_USER_REQUEST, DEFAULT_PORT_WEB_UI


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
LAMBDA_REMOTE_DOCKER = os.environ.get('LAMBDA_REMOTE_DOCKER', '').lower().strip() in ['true', '1']

# network that the docker lambda container will be joining
LAMBDA_DOCKER_NETWORK = os.environ.get('LAMBDA_DOCKER_NETWORK', '').strip()

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), 'localstack')
# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith('/var/folders/') and os.path.exists('/private%s' % TMP_FOLDER):
    TMP_FOLDER = '/private%s' % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set
HOST_TMP_FOLDER = os.environ.get('HOST_TMP_FOLDER', TMP_FOLDER)

# directory for persisting data
DATA_DIR = os.environ.get('DATA_DIR', '').strip()

# whether to use SSL encryption for the services
USE_SSL = os.environ.get('USE_SSL', '').strip() not in ('0', 'false', '')

# default encoding used to convert strings to byte arrays (mainly for Python 3 compatibility)
DEFAULT_ENCODING = 'utf-8'

# path to local Docker UNIX domain socket
DOCKER_SOCK = os.environ.get('DOCKER_SOCK', '').strip() or '/var/run/docker.sock'

# port of Web UI
PORT_WEB_UI = int(os.environ.get('PORT_WEB_UI', '').strip() or DEFAULT_PORT_WEB_UI)

# IP of the docker bridge used to enable access between containers
DOCKER_BRIDGE_IP = os.environ.get('DOCKER_BRIDGE_IP', '').strip() or '172.17.0.1'

# whether to use Lambda functions in a Docker container
LAMBDA_EXECUTOR = os.environ.get('LAMBDA_EXECUTOR', '').strip()
if not LAMBDA_EXECUTOR:
    LAMBDA_EXECUTOR = 'local'
    try:
        if 'Linux' in subprocess.check_output('uname -a'):
            LAMBDA_EXECUTOR = 'docker'
    except Exception:
        pass

# Fallback URL to use when a non-existing Lambda is invoked. If this matches
# `dynamodb://<table_name>`, then the invocation is recorded in the corresponding
# DynamoDB table. If this matches `http(s)://...`, then the Lambda invocation is
# forwarded as a POST request to that URL.
LAMBDA_FALLBACK_URL = os.environ.get('LAMBDA_FALLBACK_URL', '').strip()

# list of environment variable names used for configuration.
# Make sure to keep this in sync with the above!
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = ['SERVICES', 'HOSTNAME', 'HOSTNAME_EXTERNAL', 'LOCALSTACK_HOSTNAME', 'LAMBDA_FALLBACK_URL',
    'LAMBDA_EXECUTOR', 'LAMBDA_REMOTE_DOCKER', 'LAMBDA_DOCKER_NETWORK', 'USE_SSL', 'LICENSE_KEY', 'DEBUG',
    'KINESIS_ERROR_PROBABILITY', 'DYNAMODB_ERROR_PROBABILITY', 'PORT_WEB_UI', 'START_WEB', 'DOCKER_BRIDGE_IP']

for key, value in iteritems(DEFAULT_SERVICE_PORTS):
    clean_key = key.upper().replace('-', '_')
    CONFIG_ENV_VARS += [clean_key + '_BACKEND', clean_key + '_PORT_EXTERNAL']

# create variable aliases prefixed with LOCALSTACK_ (except LOCALSTACK_HOSTNAME)
CONFIG_ENV_VARS += ['LOCALSTACK_' + v for v in CONFIG_ENV_VARS]


def in_docker():
    """ Returns: True if running in a docker container, else False """
    if not os.path.exists('/proc/1/cgroup'):
        return False
    with open('/proc/1/cgroup', 'rt') as ifh:
        return 'docker' in ifh.read()


is_in_docker = in_docker()

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

# create folders
for folder in [DATA_DIR, TMP_FOLDER]:
    if folder and not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except Exception:
            # this can happen due to a race condition when starting
            # multiple processes in parallel. Should be safe to ignore
            pass

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
    """ Parses the environment variable $SERVICE_PORTS with a comma-separated list of services
        and (optional) ports they should run on: 'service1:port1,service2,service3:port3' """
    service_ports = os.environ.get('SERVICES', '').strip()
    if not service_ports:
        return DEFAULT_SERVICE_PORTS
    result = {}
    for service_port in re.split(r'\s*,\s*', service_ports):
        parts = re.split(r'[:=]', service_port)
        service = parts[0]
        result[service] = int(parts[-1]) if len(parts) > 1 else DEFAULT_SERVICE_PORTS.get(service)
    return result


def populate_configs(service_ports=None):
    global SERVICE_PORTS

    SERVICE_PORTS = service_ports or parse_service_ports()
    globs = globals()

    # define service ports and URLs as environment variables
    for key, value in iteritems(DEFAULT_SERVICE_PORTS):
        key_upper = key.upper().replace('-', '_')

        # define PORT_* variables with actual service ports as per configuration
        port_key = 'PORT_%s' % key_upper
        globs[port_key] = SERVICE_PORTS.get(key, 0)
        url = 'http%s://%s:%s' % ('s' if USE_SSL else '', LOCALSTACK_HOSTNAME, SERVICE_PORTS.get(key, 0))
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
if os.environ.get('DEBUG', '').lower() in ('1', 'true'):
    logging.getLogger('').setLevel(logging.DEBUG)
    logging.getLogger('localstack').setLevel(logging.DEBUG)

# set URL pattern of inbound API gateway
INBOUND_GATEWAY_URL_PATTERN = ('%s/restapis/{api_id}/{stage_name}/%s{path}' %
    (TEST_APIGATEWAY_URL, PATH_USER_REQUEST))  # noqa
