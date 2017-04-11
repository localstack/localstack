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
DEFAULT_PORT_REDSHIFT = 4577
DEFAULT_PORT_ES = 4578
# backend service ports (for services that are behind a proxy)
DEFAULT_PORT_APIGATEWAY_BACKEND = 4579
DEFAULT_PORT_KINESIS_BACKEND = 4580
DEFAULT_PORT_DYNAMODB_BACKEND = 4581
DEFAULT_PORT_SNS_BACKEND = 4582
DEFAULT_PORT_ELASTICSEARCH_BACKEND = 4583

DEFAULT_PORT_WEB_UI = 8080

LOCALHOST = 'localhost'

# map of default service APIs and ports to be spun up
DEFAULT_SERVICE_PORTS = {
    'es': DEFAULT_PORT_ES,
    'elasticsearch': DEFAULT_PORT_ELASTICSEARCH,
    's3': DEFAULT_PORT_S3,
    'sns': DEFAULT_PORT_SNS,
    'sqs': DEFAULT_PORT_SQS,
    'apigateway': DEFAULT_PORT_APIGATEWAY,
    'dynamodb': DEFAULT_PORT_DYNAMODB,
    'dynamodbstreams': DEFAULT_PORT_DYNAMODBSTREAMS,
    'firehose': DEFAULT_PORT_FIREHOSE,
    'lambda': DEFAULT_PORT_LAMBDA,
    'kinesis': DEFAULT_PORT_KINESIS,
    'redshift': DEFAULT_PORT_REDSHIFT
}

# host to bind to when starting the services
BIND_HOST = '0.0.0.0'

# AWS user account ID used for tests
TEST_AWS_ACCOUNT_ID = '123456789'
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

# action headers
KINESIS_ACTION_PUT_RECORD = 'Kinesis_20131202.PutRecord'
KINESIS_ACTION_PUT_RECORDS = 'Kinesis_20131202.PutRecords'

# content types
APPLICATION_AMZ_JSON_1_0 = 'application/x-amz-json-1.0'
APPLICATION_AMZ_JSON_1_1 = 'application/x-amz-json-1.1'
APPLICATION_JSON = 'application/json'

# Lambda defaults
LAMBDA_TEST_ROLE = "arn:aws:iam::%s:role/lambda-test-role" % TEST_AWS_ACCOUNT_ID
LAMBDA_MAIN_SCRIPT_NAME = 'handler.py'

# installation constants
ELASTICSEARCH_JAR_URL = ('https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.3.0.zip')
