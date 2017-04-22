import re
from localstack.constants import *

# Randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = 0.0
if os.environ.get('KINESIS_ERROR_PROBABILITY'):
    KINESIS_ERROR_PROBABILITY = float(os.environ['KINESIS_ERROR_PROBABILITY'])

# Randomly inject faults to DynamoDB
DYNAMODB_ERROR_PROBABILITY = 0.0
if os.environ.get('DYNAMODB_ERROR_PROBABILITY'):
    DYNAMODB_ERROR_PROBABILITY = float(os.environ['DYNAMODB_ERROR_PROBABILITY'])

# Allow custom hostname for services
HOSTNAME = LOCALHOST
if os.environ.get('HOSTNAME'):
    HOSTNAME = os.environ['HOSTNAME']


def parse_service_ports():
    """ Parses the environment variable $SERVICE_PORTS with a comma-separated list of services
        and (optional) ports they should run on: 'service1:port1,service2,service3:port3' """
    service_ports = os.environ.get('SERVICES')
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
for key, value in DEFAULT_SERVICE_PORTS.iteritems():
    # define PORT_* variables with actual service ports as per configuration
    exec('PORT_%s = SERVICE_PORTS.get("%s")' % (key.upper(), key))
    url = "http://%s:%s" % (HOSTNAME, SERVICE_PORTS.get(key))
    # define TEST_*_URL variables with mock service endpoints
    exec('TEST_%s_URL = "%s"' % (key.upper(), url))
    # expose HOST_*_URL variables as environment variables
    os.environ['TEST_%s_URL' % key.upper()] = url
