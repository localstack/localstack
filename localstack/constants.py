import os
import localstack_client.config

# LocalStack version
VERSION = '0.8.3'

# default AWS region
if 'DEFAULT_REGION' not in os.environ:
    os.environ['DEFAULT_REGION'] = 'us-east-1'
DEFAULT_REGION = os.environ['DEFAULT_REGION']

# constant to represent the "local" region, i.e., local machine
REGION_LOCAL = 'local'

# dev environment
ENV_DEV = 'dev'

# backend service ports, for services that are behind a proxy (counting down from 4566)
DEFAULT_PORT_APIGATEWAY_BACKEND = 4566
DEFAULT_PORT_KINESIS_BACKEND = 4565
DEFAULT_PORT_DYNAMODB_BACKEND = 4564
DEFAULT_PORT_S3_BACKEND = 4563
DEFAULT_PORT_SNS_BACKEND = 4562
DEFAULT_PORT_SQS_BACKEND = 4561
DEFAULT_PORT_ELASTICSEARCH_BACKEND = 4560
DEFAULT_PORT_CLOUDFORMATION_BACKEND = 4559

DEFAULT_PORT_WEB_UI = 8080

LOCALHOST = 'localhost'

# version of the Maven dependency with Java utility code
LOCALSTACK_MAVEN_VERSION = '0.1.7'

# map of default service APIs and ports to be spun up (fetch map from localstack_client)
DEFAULT_SERVICE_PORTS = localstack_client.config.get_service_ports()

# host to bind to when starting the services
BIND_HOST = '0.0.0.0'

# AWS user account ID used for tests
TEST_AWS_ACCOUNT_ID = '000000000000'
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

# name of LocalStack Docker image
DOCKER_IMAGE_NAME = 'localstack/localstack'

# environment variable name to tag local test runs
ENV_INTERNAL_TEST_RUN = 'LOCALSTACK_INTERNAL_TEST_RUN'

# content types
APPLICATION_AMZ_JSON_1_0 = 'application/x-amz-json-1.0'
APPLICATION_AMZ_JSON_1_1 = 'application/x-amz-json-1.1'
APPLICATION_JSON = 'application/json'

# Lambda defaults
LAMBDA_TEST_ROLE = 'arn:aws:iam::%s:role/lambda-test-role' % TEST_AWS_ACCOUNT_ID

# installation constants
ELASTICSEARCH_JAR_URL = 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.3.0.zip'
DYNAMODB_JAR_URL = 'https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip'
ELASTICMQ_JAR_URL = 'https://s3-eu-west-1.amazonaws.com/softwaremill-public/elasticmq-server-0.13.8.jar'
STS_JAR_URL = 'http://central.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar'

# API endpoint for analytics events
API_ENDPOINT = 'https://api.localstack.cloud/v1'
