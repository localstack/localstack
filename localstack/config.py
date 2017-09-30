import re
import os
import socket
import subprocess
import tempfile
from os.path import expanduser
from six import iteritems
from localstack.constants import DEFAULT_SERVICE_PORTS, LOCALHOST, PATH_USER_REQUEST, DEFAULT_PORT_WEB_UI

# randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = float(os.environ.get('KINESIS_ERROR_PROBABILITY', '').strip() or 0.0)

# randomly inject faults to DynamoDB
DYNAMODB_ERROR_PROBABILITY = float(os.environ.get('DYNAMODB_ERROR_PROBABILITY', '').strip() or 0.0)

# expose services on a specific host internally
HOSTNAME = os.environ.get('HOSTNAME', '').strip() or LOCALHOST

# expose services on a specific host externally
HOSTNAME_EXTERNAL = os.environ.get('HOSTNAME_EXTERNAL', '').strip() or LOCALHOST

# name of the host under which the LocalStack services are available
LOCALSTACK_HOSTNAME = os.environ.get('LOCALSTACK_HOSTNAME', '').strip() or HOSTNAME

# whether to remotely copy the lambda or locally mount a volume
LAMBDA_REMOTE_DOCKER = os.environ.get('LAMBDA_REMOTE_DOCKER', '').lower().strip() in ['true', '1']

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

# whether to use Lambda functions in a Docker container
LAMBDA_EXECUTOR = os.environ.get('LAMBDA_EXECUTOR', '').strip()
if not LAMBDA_EXECUTOR:
    LAMBDA_EXECUTOR = 'local'
    try:
        if 'Linux' in subprocess.check_output('uname -a'):
            LAMBDA_EXECUTOR = 'docker'
    except Exception as e:
        pass

# list of environment variable names used for configuration.
# Make sure to keep this in sync with the above!
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = ['SERVICES', 'HOSTNAME', 'HOSTNAME_EXTERNAL', 'LOCALSTACK_HOSTNAME',
    'LAMBDA_EXECUTOR', 'LAMBDA_REMOTE_DOCKER', 'USE_SSL', 'LICENSE_KEY', 'DEBUG',
    'KINESIS_ERROR_PROBABILITY', 'DYNAMODB_ERROR_PROBABILITY', 'PORT_WEB_UI']
for key, value in iteritems(DEFAULT_SERVICE_PORTS):
    backend_override_var = '%s_BACKEND' % key.upper().replace('-', '_')
    if os.environ.get(backend_override_var):
        CONFIG_ENV_VARS.append(backend_override_var)

def in_docker():
    """ Returns: True if running in a docker container, else False """
    if not os.path.exists('/proc/1/cgroup'):
        return False
    with open('/proc/1/cgroup', 'rt') as ifh:
        return 'docker' in ifh.read()

# determine route to Docker host from container
DOCKER_BRIDGE_IP = '172.17.0.1'
try:
    DOCKER_HOST_FROM_CONTAINER = socket.gethostbyname('docker.for.mac.localhost')
    # update LOCALSTACK_HOSTNAME if docker.for.mac.localhost is available
    if in_docker() and LOCALSTACK_HOSTNAME == DOCKER_BRIDGE_IP:
        LOCALSTACK_HOSTNAME = DOCKER_HOST_FROM_CONTAINER
except socket.error:
    DOCKER_HOST_FROM_CONTAINER = DOCKER_BRIDGE_IP

# local config file path in home directory
CONFIG_FILE_PATH = os.path.join(expanduser("~"), '.localstack')

# create folders
for folder in [DATA_DIR, TMP_FOLDER]:
    if folder and not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except Exception as e:
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
    # Fix Elasticsearch port - we have 'es' (AWS ES API) and 'elasticsearch' (actual Elasticsearch API)
    if result.get('es') and not result.get('elasticsearch'):
        result['elasticsearch'] = DEFAULT_SERVICE_PORTS.get('elasticsearch')
    return result


def populate_configs():
    global SERVICE_PORTS

    SERVICE_PORTS = parse_service_ports()

    # define service ports and URLs as environment variables
    for key, value in iteritems(DEFAULT_SERVICE_PORTS):
        key_upper = key.upper().replace('-', '_')

        # define PORT_* variables with actual service ports as per configuration
        exec('global PORT_%s; PORT_%s = SERVICE_PORTS.get("%s", 0)' % (key_upper, key_upper, key))
        url = 'http%s://%s:%s' % ('s' if USE_SSL else '', LOCALSTACK_HOSTNAME, SERVICE_PORTS.get(key, 0))
        # define TEST_*_URL variables with mock service endpoints
        exec('global TEST_%s_URL; TEST_%s_URL = "%s"' % (key_upper, key_upper, url))
        # expose HOST_*_URL variables as environment variables
        os.environ['TEST_%s_URL' % key_upper] = url

    # expose LOCALSTACK_HOSTNAME as env. variable
    os.environ['LOCALSTACK_HOSTNAME'] = LOCALSTACK_HOSTNAME


def service_port(service_key):
    return SERVICE_PORTS.get(service_key, 0)


# initialize config values
populate_configs()


# set URL pattern of inbound API gateway
INBOUND_GATEWAY_URL_PATTERN = ('%s/restapis/{api_id}/{stage_name}/%s{path}' %
    (TEST_APIGATEWAY_URL, PATH_USER_REQUEST))  # flake8: noqa
