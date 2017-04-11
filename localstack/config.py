import re
from localstack.constants import *

# Randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = 0.0
if os.environ.get('KINESIS_ERROR_PROBABILITY'):
    KINESIS_ERROR_PROBABILITY = float(os.environ['KINESIS_ERROR_PROBABILITY'])

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

# determine actual service ports
PORT_APIGATEWAY = SERVICE_PORTS.get('apigateway')
PORT_KINESIS = SERVICE_PORTS.get('kinesis')
PORT_DYNAMODB = SERVICE_PORTS.get('dynamodb')
PORT_DYNAMODBSTREAMS = SERVICE_PORTS.get('dynamodbstreams')
PORT_ELASTICSEARCH = SERVICE_PORTS.get('elasticsearch')
PORT_ES = SERVICE_PORTS.get('es')
PORT_S3 = SERVICE_PORTS.get('s3')
PORT_FIREHOSE = SERVICE_PORTS.get('firehose')
PORT_LAMBDA = SERVICE_PORTS.get('lambda')
PORT_SNS = SERVICE_PORTS.get('sns')
PORT_SQS = SERVICE_PORTS.get('sqs')
PORT_REDSHIFT = SERVICE_PORTS.get('redshift')

# default mock service endpoints
TEST_KINESIS_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_KINESIS)
TEST_FIREHOSE_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_FIREHOSE)
TEST_DYNAMODB_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_DYNAMODB)
TEST_LAMBDA_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_LAMBDA)
TEST_ES_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_ES)
TEST_ELASTICSEARCH_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_ELASTICSEARCH)
TEST_DYNAMODBSTREAMS_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_DYNAMODBSTREAMS)
TEST_S3_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_S3)
TEST_SNS_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_SNS)
TEST_SQS_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_SQS)
TEST_APIGATEWAY_URL = 'http://%s:%s' % (HOSTNAME, DEFAULT_PORT_APIGATEWAY)

# expose constants as environment variables
os.environ['TEST_DYNAMODB_URL'] = TEST_DYNAMODB_URL
os.environ['TEST_KINESIS_URL'] = TEST_KINESIS_URL
os.environ['TEST_S3_URL'] = TEST_S3_URL
os.environ['TEST_SNS_URL'] = TEST_SNS_URL
os.environ['TEST_SQS_URL'] = TEST_SQS_URL
os.environ['TEST_APIGATEWAY_URL'] = TEST_APIGATEWAY_URL
os.environ['TEST_LAMBDA_URL'] = TEST_LAMBDA_URL
os.environ['TEST_FIREHOSE_URL'] = TEST_FIREHOSE_URL
os.environ['TEST_ELASTICSEARCH_URL'] = TEST_ELASTICSEARCH_URL
os.environ['TEST_ES_URL'] = TEST_ES_URL
os.environ['TEST_DYNAMODBSTREAMS_URL'] = TEST_DYNAMODBSTREAMS_URL
