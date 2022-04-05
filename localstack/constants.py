import os

import localstack_client.config

import localstack

# LocalStack version
VERSION = localstack.__version__

# constant to represent the "local" region, i.e., local machine
REGION_LOCAL = "local"

# dev environment
ENV_DEV = "dev"

# HTTP headers used to forward proxy request URLs
HEADER_LOCALSTACK_EDGE_URL = "x-localstack-edge"
HEADER_LOCALSTACK_REQUEST_URL = "x-localstack-request-url"
HEADER_LOCALSTACK_AUTHORIZATION = "x-localstack-authorization"
HEADER_LOCALSTACK_TARGET = "x-localstack-target"
HEADER_AMZN_ERROR_TYPE = "X-Amzn-Errortype"

# backend service ports, for services that are behind a proxy (counting down from 4566)
DEFAULT_PORT_EDGE = 4566

# host name for localhost
LOCALHOST = "localhost"
LOCALHOST_IP = "127.0.0.1"
LOCALHOST_HOSTNAME = "localhost.localstack.cloud"

# version of the Maven dependency with Java utility code
LOCALSTACK_MAVEN_VERSION = "0.2.19"

# map of default service APIs and ports to be spun up (fetch map from localstack_client)
DEFAULT_SERVICE_PORTS = localstack_client.config.get_service_ports()

# host to bind to when starting the services
BIND_HOST = "0.0.0.0"

# AWS user account ID used for tests - TODO move to config.py
if "TEST_AWS_ACCOUNT_ID" not in os.environ:
    os.environ["TEST_AWS_ACCOUNT_ID"] = "000000000000"
TEST_AWS_ACCOUNT_ID = os.environ["TEST_AWS_ACCOUNT_ID"]

# root code folder
MODULE_MAIN_PATH = os.path.dirname(os.path.realpath(__file__))
# TODO rename to "ROOT_FOLDER"!
LOCALSTACK_ROOT_FOLDER = os.path.realpath(os.path.join(MODULE_MAIN_PATH, ".."))
INSTALL_DIR_INFRA = os.path.join(
    MODULE_MAIN_PATH, "infra"
)  # FIXME: deprecated, use config.dirs.infra

# virtualenv folder
LOCALSTACK_VENV_FOLDER = os.environ.get("VIRTUAL_ENV")
if not LOCALSTACK_VENV_FOLDER:
    # fallback to the previous logic
    LOCALSTACK_VENV_FOLDER = os.path.join(LOCALSTACK_ROOT_FOLDER, ".venv")
    if not os.path.isdir(LOCALSTACK_VENV_FOLDER):
        # assuming this package lives here: <python>/lib/pythonX.X/site-packages/localstack/
        LOCALSTACK_VENV_FOLDER = os.path.realpath(
            os.path.join(LOCALSTACK_ROOT_FOLDER, "..", "..", "..")
        )

# API Gateway path to indicate a user request sent to the gateway
PATH_USER_REQUEST = "_user_request_"

# name of LocalStack Docker image
DOCKER_IMAGE_NAME = "localstack/localstack"
DOCKER_IMAGE_NAME_FULL = "localstack/localstack-full"

# backdoor API path used to retrieve or update config variables
CONFIG_UPDATE_PATH = "/?_config_"

# API path for localstack internal resources
INTERNAL_RESOURCE_PATH = "/_localstack"

# environment variable name to tag local test runs
ENV_INTERNAL_TEST_RUN = "LOCALSTACK_INTERNAL_TEST_RUN"

# environment variable that flags whether pro was activated. do not use for security purposes!
ENV_PRO_ACTIVATED = "PRO_ACTIVATED"

# content types / encodings
HEADER_CONTENT_TYPE = "Content-Type"
APPLICATION_AMZ_JSON_1_0 = "application/x-amz-json-1.0"
APPLICATION_AMZ_JSON_1_1 = "application/x-amz-json-1.1"
APPLICATION_AMZ_CBOR_1_1 = "application/x-amz-cbor-1.1"
APPLICATION_CBOR = "application/cbor"
APPLICATION_JSON = "application/json"
APPLICATION_XML = "application/xml"
APPLICATION_OCTET_STREAM = "application/octet-stream"
APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded"
HEADER_ACCEPT_ENCODING = "Accept-Encoding"

# strings to indicate truthy/falsy values
TRUE_STRINGS = ("1", "true", "True")
FALSE_STRINGS = ("0", "false", "False")
# strings with valid log levels for LS_LOG
LOG_LEVELS = ("trace-internal", "trace", "debug", "info", "warn", "error", "warning")

# Lambda defaults
LAMBDA_TEST_ROLE = "arn:aws:iam::%s:role/lambda-test-role" % TEST_AWS_ACCOUNT_ID

# the version of elasticsearch that is pre-seeded into the base image (sync with Dockerfile.base)
ELASTICSEARCH_DEFAULT_VERSION = "Elasticsearch_7.10"
# See https://docs.aws.amazon.com/ja_jp/elasticsearch-service/latest/developerguide/aes-supported-plugins.html
ELASTICSEARCH_PLUGIN_LIST = [
    "analysis-icu",
    "ingest-attachment",
    "analysis-kuromoji",
    "mapper-murmur3",
    "mapper-size",
    "analysis-phonetic",
    "analysis-smartcn",
    "analysis-stempel",
    "analysis-ukrainian",
]
# Default ES modules to exclude (save apprx 66MB in the final image)
ELASTICSEARCH_DELETE_MODULES = ["ingest-geoip"]

# the version of opensearch which is used by default
OPENSEARCH_DEFAULT_VERSION = "OpenSearch_1.1"

ELASTICMQ_JAR_URL = (
    "https://s3-eu-west-1.amazonaws.com/softwaremill-public/elasticmq-server-1.1.0.jar"
)
STS_JAR_URL = "https://repo1.maven.org/maven2/com/amazonaws/aws-java-sdk-sts/1.11.14/aws-java-sdk-sts-1.11.14.jar"
STEPFUNCTIONS_ZIP_URL = "https://s3.amazonaws.com/stepfunctionslocal/StepFunctionsLocal.zip"
KMS_URL_PATTERN = "https://s3-eu-west-2.amazonaws.com/local-kms/3/local-kms_<arch>.bin"

DYNAMODB_JAR_URL = "https://s3-us-west-2.amazonaws.com/dynamodb-local/dynamodb_local_latest.zip"

# API endpoint for analytics events
API_ENDPOINT = os.environ.get("API_ENDPOINT") or "https://api.localstack.cloud/v1"
# new analytics API endpoint
ANALYTICS_API = os.environ.get("ANALYTICS_API") or "https://analytics.localstack.cloud/v0"

# environment variable to indicates that this process is running the Web UI
LOCALSTACK_WEB_PROCESS = "LOCALSTACK_WEB_PROCESS"
LOCALSTACK_INFRA_PROCESS = "LOCALSTACK_INFRA_PROCESS"

# default AWS region us-east-1
AWS_REGION_US_EAST_1 = "us-east-1"

# default lambda registry
DEFAULT_LAMBDA_CONTAINER_REGISTRY = "lambci/lambda"

# environment variable to override max pool connections
try:
    MAX_POOL_CONNECTIONS = int(os.environ["MAX_POOL_CONNECTIONS"])
except Exception:
    MAX_POOL_CONNECTIONS = 150

# test credentials used for generating signature for S3 presigned URLs (to be used by external clients)
TEST_AWS_ACCESS_KEY_ID = "test"
TEST_AWS_SECRET_ACCESS_KEY = "test"

# credentials being used for internal calls
INTERNAL_AWS_ACCESS_KEY_ID = "__internal_call__"
INTERNAL_AWS_SECRET_ACCESS_KEY = "__internal_call__"

# trace log levels (excluding/including internal API calls), configurable via $LS_LOG
LS_LOG_TRACE = "trace"
LS_LOG_TRACE_INTERNAL = "trace-internal"
TRACE_LOG_LEVELS = [LS_LOG_TRACE, LS_LOG_TRACE_INTERNAL]

# list of official docker images
OFFICIAL_IMAGES = [
    "localstack/localstack",
    "localstack/localstack-light",
    "localstack/localstack-full",
]

# s3 virtual host name
S3_VIRTUAL_HOSTNAME = "s3.%s" % LOCALHOST_HOSTNAME
S3_STATIC_WEBSITE_HOSTNAME = "s3-website.%s" % LOCALHOST_HOSTNAME

# port for debug py
DEFAULT_DEVELOP_PORT = 5678

# Default bucket name of the s3 bucket used for local lambda development
DEFAULT_BUCKET_MARKER_LOCAL = "__local__"

# user that starts the opensearch process if the current user is root
OS_USER_OPENSEARCH = "localstack"

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = "Ready."

# hardcoded AWS account ID used by moto
MOTO_ACCOUNT_ID = TEST_AWS_ACCOUNT_ID


def patch_moto_account_id():
    # fix moto account ID - note: this needs to be executed before any other moto imports
    try:
        from moto import core as moto_core
        from moto.core import models as moto_core_models

        moto_core.ACCOUNT_ID = moto_core_models.ACCOUNT_ID = MOTO_ACCOUNT_ID
    except Exception:
        # ignore import errors
        pass


if not os.environ.get("SKIP_PATCH_MOTO_ACCOUNT_ID"):
    # allow skipping this (importing moto takes a long time, and it's not necessary for the CLI)
    patch_moto_account_id()
