import os

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
# xXx custom localstack authorization header only used in ext
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
LOCALSTACK_MAVEN_VERSION = "0.2.21"
MAVEN_REPO_URL = "https://repo1.maven.org/maven2"

# URL of localstack's artifacts repository on GitHub
ARTIFACTS_REPO = "https://github.com/localstack/localstack-artifacts"

# Download URLs
SSL_CERT_URL = f"{ARTIFACTS_REPO}/raw/master/local-certs/server.key"
SSL_CERT_URL_FALLBACK = "{api_endpoint}/proxy/localstack.cert.key"

# host to bind to when starting the services
BIND_HOST = "0.0.0.0"

# root code folder
MODULE_MAIN_PATH = os.path.dirname(os.path.realpath(__file__))
# TODO rename to "ROOT_FOLDER"!
LOCALSTACK_ROOT_FOLDER = os.path.realpath(os.path.join(MODULE_MAIN_PATH, ".."))

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

# default volume directory containing shared data
DEFAULT_VOLUME_DIR = "/var/lib/localstack"

# API Gateway path to indicate a user request sent to the gateway
PATH_USER_REQUEST = "_user_request_"

# name of LocalStack Docker image
DOCKER_IMAGE_NAME = "localstack/localstack"
DOCKER_IMAGE_NAME_PRO = "localstack/localstack-pro"
DOCKER_IMAGE_NAME_FULL = "localstack/localstack-full"

# backdoor API path used to retrieve or update config variables
CONFIG_UPDATE_PATH = "/?_config_"

# API path for localstack internal resources
INTERNAL_RESOURCE_PATH = "/_localstack"

# environment variable name to tag local test runs
ENV_INTERNAL_TEST_RUN = "LOCALSTACK_INTERNAL_TEST_RUN"

# environment variable name to tag collect metrics during a test run
ENV_INTERNAL_TEST_COLLECT_METRIC = "LOCALSTACK_INTERNAL_TEST_COLLECT_METRIC"

# environment variable that flags whether pro was activated. do not use for security purposes!
ENV_PRO_ACTIVATED = "PRO_ACTIVATED"

# content types / encodings
HEADER_CONTENT_TYPE = "Content-Type"
TEXT_XML = "text/xml"
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
OPENSEARCH_DEFAULT_VERSION = "OpenSearch_2.9"

# See https://docs.aws.amazon.com/opensearch-service/latest/developerguide/supported-plugins.html
OPENSEARCH_PLUGIN_LIST = [
    "ingest-attachment",
]

# API endpoint for analytics events
API_ENDPOINT = os.environ.get("API_ENDPOINT") or "https://api.localstack.cloud/v1"
# new analytics API endpoint
ANALYTICS_API = os.environ.get("ANALYTICS_API") or "https://analytics.localstack.cloud/v1"

# environment variable to indicates this process should run the localstack infrastructure
LOCALSTACK_INFRA_PROCESS = "LOCALSTACK_INFRA_PROCESS"

# AWS region us-east-1
AWS_REGION_US_EAST_1 = "us-east-1"

# environment variable to override max pool connections
try:
    MAX_POOL_CONNECTIONS = int(os.environ["MAX_POOL_CONNECTIONS"])
except Exception:
    MAX_POOL_CONNECTIONS = 150

# Fallback Account ID if not available in the client request
DEFAULT_AWS_ACCOUNT_ID = "000000000000"

# Credentials used in the test suite
# These can be overridden if the tests are being run against AWS
# If a structured access key ID is used, it must correspond to the account ID
TEST_AWS_ACCOUNT_ID = os.getenv("TEST_AWS_ACCOUNT_ID") or DEFAULT_AWS_ACCOUNT_ID
TEST_AWS_ACCESS_KEY_ID = os.getenv("TEST_AWS_ACCESS_KEY_ID") or "test"
TEST_AWS_SECRET_ACCESS_KEY = os.getenv("TEST_AWS_SECRET_ACCESS_KEY") or "test"
TEST_AWS_REGION_NAME = os.getenv("TEST_AWS_REGION") or "us-east-1"

# Additional credentials used in the test suite (when running cross-account tests)
SECONDARY_TEST_AWS_ACCOUNT_ID = os.getenv("SECONDARY_TEST_AWS_ACCOUNT_ID") or "000000000002"
SECONDARY_TEST_AWS_ACCESS_KEY_ID = os.getenv("SECONDARY_TEST_AWS_ACCESS_KEY_ID") or "000000000002"
SECONDARY_TEST_AWS_SECRET_ACCESS_KEY = os.getenv("SECONDARY_TEST_AWS_SECRET_ACCESS_KEY") or "test2"
SECONDARY_TEST_AWS_REGION_NAME = os.getenv("SECONDARY_TEST_AWS_REGION") or "ap-southeast-1"

# Credentials used for internal calls
INTERNAL_AWS_ACCESS_KEY_ID = "__internal_call__"
INTERNAL_AWS_SECRET_ACCESS_KEY = "__internal_call__"

# This header must be set to the AWS Account ID
# Presence of this header in an incoming request typically means that the request originated within localstack,
# i.e. it is an internal cross-service call.
HEADER_LOCALSTACK_ACCOUNT_ID = "x-localstack-account-id"

# trace log levels (excluding/including internal API calls), configurable via $LS_LOG
LS_LOG_TRACE = "trace"
LS_LOG_TRACE_INTERNAL = "trace-internal"
TRACE_LOG_LEVELS = [LS_LOG_TRACE, LS_LOG_TRACE_INTERNAL]

# list of official docker images
OFFICIAL_IMAGES = [
    "localstack/localstack",
    "localstack/localstack-pro",
]

# port for debug py
DEFAULT_DEVELOP_PORT = 5678

# Default bucket name of the s3 bucket used for local lambda development
# This name should be accepted by all IaC tools, so should respect s3 bucket naming conventions
DEFAULT_BUCKET_MARKER_LOCAL = "hot-reload"
LEGACY_DEFAULT_BUCKET_MARKER_LOCAL = "__local__"

# user that starts the opensearch process if the current user is root
OS_USER_OPENSEARCH = "localstack"

# output string that indicates that the stack is ready
READY_MARKER_OUTPUT = "Ready."

# Regex for `Credential` field in the Authorization header in AWS signature version v4
# The format is as follows:
#   Credential=<access-key-id>/<date>/<region-name>/<service-name>/aws4_request
# eg.
#   Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request
AUTH_CREDENTIAL_REGEX = r"Credential=(?P<access_key_id>[a-zA-Z0-9-_.]{1,})/(?P<date>\d{8})/(?P<region_name>[a-z0-9-]{1,})/(?P<service_name>[a-z0-9]{1,})/"
