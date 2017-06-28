import re
import os
import subprocess
import tempfile
from six import iteritems
from localstack.constants import *

# Randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = float(os.environ.get('KINESIS_ERROR_PROBABILITY', '').strip() or 0.0)

# Randomly inject faults to DynamoDB
DYNAMODB_ERROR_PROBABILITY = float(os.environ.get('DYNAMODB_ERROR_PROBABILITY', '').strip() or 0.0)

# Allow custom hostname for services
HOSTNAME = os.environ.get('HOSTNAME', '').strip() or LOCALHOST

# whether to remotely copy the lambda or locally mount a volume
LAMBDA_REMOTE_DOCKER = os.environ.get('LAMBDA_REMOTE_DOCKER', '').strip() == 'true'

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), 'localstack')
# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith('/var/folders/') and os.path.exists('/private%s' % TMP_FOLDER):
    TMP_FOLDER = '/private%s' % TMP_FOLDER

# directory for persisting data
DATA_DIR = os.environ.get('DATA_DIR', '').strip()

# whether to use SSL encryption for the services
USE_SSL = os.environ.get('USE_SSL', '').strip() not in ('0', 'false', '')

# default encoding used to convert strings to byte arrays (mainly for Python 3 compatibility)
DEFAULT_ENCODING = 'utf-8'

# path to local Docker UNIX domain socket
DOCKER_SOCK = os.environ.get('DOCKER_SOCK', '').strip() or '/var/run/docker.sock'

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
CONFIG_ENV_VARS = ('SERVICES', 'DEBUG', 'DATA_DIR', 'HOSTNAME',
    'LAMBDA_EXECUTOR', 'LAMBDA_REMOTE_DOCKER', 'USE_SSL',
    'KINESIS_ERROR_PROBABILITY', 'DYNAMODB_ERROR_PROBABILITY')

# create folders
for folder in [DATA_DIR, TMP_FOLDER]:
    if folder and not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except Exception as e:
            # this can happen due to a race condition when starting
            # multiple processes in parallel. Should be safe to ignore
            pass


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


SERVICE_PORTS = parse_service_ports()

# define service ports and URLs as environment variables
for key, value in iteritems(DEFAULT_SERVICE_PORTS):
    # define PORT_* variables with actual service ports as per configuration
    exec('PORT_%s = SERVICE_PORTS.get("%s")' % (key.upper(), key))
    url = "http%s://%s:%s" % ('s' if USE_SSL else '', HOSTNAME, SERVICE_PORTS.get(key))
    # define TEST_*_URL variables with mock service endpoints
    exec('TEST_%s_URL = "%s"' % (key.upper(), url))
    # expose HOST_*_URL variables as environment variables
    os.environ['TEST_%s_URL' % key.upper()] = url


def service_port(service_key):
    return SERVICE_PORTS.get(service_key)


# set URL pattern of inbound API gateway
INBOUND_GATEWAY_URL_PATTERN = '%s/restapis/{api_id}/{stage_name}/%s{path}' % (TEST_APIGATEWAY_URL, PATH_USER_REQUEST)
