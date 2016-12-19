import os
import sys

# default AWS region
if 'DEFAULT_REGION' not in os.environ:
    os.environ['DEFAULT_REGION'] = 'us-east-1'
DEFAULT_REGION = os.environ['DEFAULT_REGION']

# constant to represent the "local" region, i.e., local machine
REGION_LOCAL = 'local'

# dev environment
ENV_DEV = 'dev'

# infra service ports
DEFAULT_PORT_APIGATEWAY = 4567
DEFAULT_PORT_KINESIS = 4568
DEFAULT_PORT_DYNAMODB = 4569
DEFAULT_PORT_DYNAMODBSTREAMS = 4570
DEFAULT_PORT_ELASTICSEARCH = 4571
DEFAULT_PORT_S3 = 4572
DEFAULT_PORT_FIREHOSE = 4573
DEFAULT_PORT_LAMBDA = 4574
DEFAULT_PORT_SNS = 4575
DEFAULT_PORT_SQS = 4576
# backend service ports (for services that are behind a proxy)
DEFAULT_PORT_APIGATEWAY_BACKEND = 4577
DEFAULT_PORT_KINESIS_BACKEND = 4578
DEFAULT_PORT_DYNAMODB_BACKEND = 4579

# default mock service endpoints
LOCALHOST = 'localhost'
TEST_KINESIS_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_KINESIS)
TEST_FIREHOSE_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_FIREHOSE)
TEST_DYNAMODB_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_DYNAMODB)
TEST_LAMBDA_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_LAMBDA)
TEST_ELASTICSEARCH_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_ELASTICSEARCH)
TEST_DYNAMODBSTREAMS_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_DYNAMODBSTREAMS)
TEST_S3_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_S3)
TEST_SNS_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_SNS)
TEST_SQS_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_SQS)
TEST_APIGATEWAY_URL = 'http://%s:%s' % (LOCALHOST, DEFAULT_PORT_APIGATEWAY)

# AWS user account ID used for tests
TEST_AWS_ACCOUNT_ID = '123456789'

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
os.environ['TEST_DYNAMODBSTREAMS_URL'] = TEST_DYNAMODBSTREAMS_URL
os.environ['TEST_AWS_ACCOUNT_ID'] = TEST_AWS_ACCOUNT_ID

# root code folder
LOCALSTACK_ROOT_FOLDER = os.path.realpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), '..'))

# virtualenv folder
LOCALSTACK_VENV_FOLDER = os.path.join(LOCALSTACK_ROOT_FOLDER, '.venv')
if not os.path.isdir(LOCALSTACK_VENV_FOLDER):
    # assuming this package lives here: <python>/lib/pythonX.X/site-packages/localstack/
    LOCALSTACK_VENV_FOLDER = os.path.realpath(os.path.join(LOCALSTACK_ROOT_FOLDER, '..', '..', '..'))

# API Gateway path to indicate a user request sent to the gateway
PATH_USER_REQUEST = '_user_request_'

# content types
APPLICATION_AMZ_JSON_1_0 = 'application/x-amz-json-1.0'
APPLICATION_AMZ_JSON_1_1 = 'application/x-amz-json-1.1'
APPLICATION_JSON = 'application/json'

# Lambda defaults
LAMBDA_TEST_ROLE = "arn:aws:iam::%s:role/lambda-test-role" % TEST_AWS_ACCOUNT_ID
LAMBDA_MAIN_SCRIPT_NAME = 'handler.py'

# installation constants
ELASTICSEARCH_JAR_URL = ('https://download.elastic.co/elasticsearch/release/org/elasticsearch/' +
    'distribution/zip/elasticsearch/2.3.3/elasticsearch-2.3.3.zip')
