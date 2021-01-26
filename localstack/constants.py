import os
import localstack_client.config

# LocalStack version
VERSION = '0.12.5'

# constant to represent the "local" region, i.e., local machine
REGION_LOCAL = 'local'

# dev environment
ENV_DEV = 'dev'

# HTTP headers used to forward proxy request URLs
HEADER_LOCALSTACK_EDGE_URL = 'x-localstack-edge'
HEADER_LOCALSTACK_TARGET = 'x-localstack-target'

# backend service ports, for services that are behind a proxy (counting down from 4566)
DEFAULT_PORT_EDGE = 4566
DEFAULT_PORT_WEB_UI = 8080

# host name for localhost
LOCALHOST = 'localhost'
LOCALHOST_IP = '127.0.0.1'

# version of the Maven dependency with Java utility code
LOCALSTACK_MAVEN_VERSION = '0.2.5'

# map of default service APIs and ports to be spun up (fetch map from localstack_client)
DEFAULT_SERVICE_PORTS = localstack_client.config.get_service_ports()

# host to bind to when starting the services
BIND_HOST = '0.0.0.0'

# AWS user account ID used for tests
if 'TEST_AWS_ACCOUNT_ID' not in os.environ:
    os.environ['TEST_AWS_ACCOUNT_ID'] = '000000000000'
TEST_AWS_ACCOUNT_ID = os.environ['TEST_AWS_ACCOUNT_ID']

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
DOCKER_IMAGE_NAME_FULL = 'localstack/localstack-full'

# backdoor API path used to retrieve or update config variables
CONFIG_UPDATE_PATH = '/?_config_'

# environment variable name to tag local test runs
ENV_INTERNAL_TEST_RUN = 'LOCALSTACK_INTERNAL_TEST_RUN'

# content types
APPLICATION_AMZ_JSON_1_0 = 'application/x-amz-json-1.0'
APPLICATION_AMZ_JSON_1_1 = 'application/x-amz-json-1.1'
APPLICATION_AMZ_CBOR_1_1 = 'application/x-amz-cbor-1.1'
APPLICATION_CBOR = 'application/cbor'
APPLICATION_JSON = 'application/json'
APPLICATION_XML = 'application/xml'
APPLICATION_X_WWW_FORM_URLENCODED = 'application/x-www-form-urlencoded'

# strings to indicate truthy/falsy values
TRUE_STRINGS = ('1', 'true', 'True')
FALSE_STRINGS = ('0', 'false', 'False')

# Lambda defaults
LAMBDA_TEST_ROLE = 'arn:aws:iam::%s:role/lambda-test-role' % TEST_AWS_ACCOUNT_ID

# installation constants
ELASTICSEARCH_URLS = {
    '7.7.0': 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.7.0-linux-x86_64.tar.gz',
    '7.4.0': 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.4.0-linux-x86_64.tar.gz',
    '7.1.0': 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-7.1.0-linux-x86_64.tar.gz',
    '6.7.0': 'https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.7.0.zip'
}
ELASTICSEARCH_DEFAULT_VERSION = '7.7.0'
# See https://docs.aws.amazon.com/ja_jp/elasticsearch-service/latest/developerguide/aes-supported-plugins.html
ELASTICSEARCH_PLUGIN_LIST = ['analysis-icu', 'ingest-attachment', 'analysis-kuromoji',
 'mapper-murmur3', 'mapper-size', 'analysis-phonetic', 'analysis-smartcn', 'analysis-stempel', 'analysis-ukrainian']
# Default ES modules to exclude (save apprx 66MB in the final image)
ELASTICSEARCH_DELETE_MODULES = ['ingest-geoip']
ELASTICMQ_JAR_URL = 'https://s3-eu-west-1.amazonaws.com/softwaremill-public/elasticmq-server-0.15.7.jar'
STS_JAR_URL = 'https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar'
STEPFUNCTIONS_ZIP_URL = 'https://s3.amazonaws.com/stepfunctionslocal/StepFunctionsLocal.zip'
KMS_URL_PATTERN = 'https://s3-eu-west-2.amazonaws.com/local-kms/localstack/v3/local-kms.<arch>.bin'

# TODO: Temporarily using a fixed version of DDB in Alpine, as we're hitting a SIGSEGV JVM crash with latest
DYNAMODB_JAR_URL_ALPINE = 'https://github.com/whummer/dynamodb-local/raw/master/etc/DynamoDBLocal.zip'
DYNAMODB_JAR_URL = 'https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip'

# API endpoint for analytics events
API_ENDPOINT = os.environ.get('API_ENDPOINT') or 'https://api.localstack.cloud/v1'

# environment variable to indicates that this process is running the Web UI
LOCALSTACK_WEB_PROCESS = 'LOCALSTACK_WEB_PROCESS'
LOCALSTACK_INFRA_PROCESS = 'LOCALSTACK_INFRA_PROCESS'

# hardcoded AWS account ID used by moto
MOTO_ACCOUNT_ID = TEST_AWS_ACCOUNT_ID
# fix moto account ID - note: keep this at the top level here
try:
    from moto import core as moto_core
    from moto.core import models as moto_core_models
    moto_core.ACCOUNT_ID = moto_core_models.ACCOUNT_ID = MOTO_ACCOUNT_ID
except Exception:
    # ignore import errors
    pass

# default AWS region us-east-1
AWS_REGION_US_EAST_1 = 'us-east-1'

# default lambda registry
DEFAULT_LAMBDA_CONTAINER_REGISTRY = 'lambci/lambda'

# environment variable to override max pool connections
try:
    MAX_POOL_CONNECTIONS = int(os.environ['MAX_POOL_CONNECTIONS'])
except Exception:
    MAX_POOL_CONNECTIONS = 150

# test credentials used for generating signature for S3 presigned URLs (to be used by external clients)
TEST_AWS_ACCESS_KEY_ID = 'test'
TEST_AWS_SECRET_ACCESS_KEY = 'test'

# credentials being used for internal calls
INTERNAL_AWS_ACCESS_KEY_ID = '__internal_call__'
INTERNAL_AWS_SECRET_ACCESS_KEY = '__internal_call__'
