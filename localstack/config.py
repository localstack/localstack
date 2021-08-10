import json
import logging
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from os.path import expanduser

import six
from boto3 import Session

from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_BUCKET_MARKER_LOCAL,
    DEFAULT_DEVELOP_PORT,
    DEFAULT_LAMBDA_CONTAINER_REGISTRY,
    DEFAULT_PORT_EDGE,
    DEFAULT_SERVICE_PORTS,
    FALSE_STRINGS,
    LOCALHOST,
    LOCALHOST_IP,
    LOG_LEVELS,
    TRUE_STRINGS,
)

# keep track of start time, for performance debugging
load_start_time = time.time()


def eval_log_type(env_var_name):
    """get the log type from environment variable"""
    ls_log = os.environ.get(env_var_name, "").lower().strip()
    return ls_log if ls_log in LOG_LEVELS else False


def is_env_true(env_var_name):
    """Whether the given environment variable has a truthy value."""
    return os.environ.get(env_var_name, "").lower().strip() in TRUE_STRINGS


def is_env_not_false(env_var_name):
    """Whether the given environment variable is empty or has a truthy value."""
    return os.environ.get(env_var_name, "").lower().strip() not in FALSE_STRINGS


# java options to Lambda
LAMBDA_JAVA_OPTS = os.environ.get("LAMBDA_JAVA_OPTS", "").strip()

# limit in which to kinesalite will start throwing exceptions
KINESIS_SHARD_LIMIT = os.environ.get("KINESIS_SHARD_LIMIT", "").strip() or "100"

# delay in kinesalite response when making changes to streams
KINESIS_LATENCY = os.environ.get("KINESIS_LATENCY", "").strip() or "500"

# Kinesis provider - either "kinesis-mock" or "kinesalite"
KINESIS_PROVIDER = os.environ.get("KINESIS_PROVIDER") or "kinesis-mock"

# default AWS region
if "DEFAULT_REGION" not in os.environ:
    os.environ["DEFAULT_REGION"] = os.environ.get("AWS_DEFAULT_REGION") or AWS_REGION_US_EAST_1
DEFAULT_REGION = os.environ["DEFAULT_REGION"]

# Whether or not to handle lambda event sources as synchronous invocations
SYNCHRONOUS_SNS_EVENTS = is_env_true("SYNCHRONOUS_SNS_EVENTS")
SYNCHRONOUS_SQS_EVENTS = is_env_true("SYNCHRONOUS_SQS_EVENTS")
SYNCHRONOUS_API_GATEWAY_EVENTS = is_env_not_false("SYNCHRONOUS_API_GATEWAY_EVENTS")
SYNCHRONOUS_KINESIS_EVENTS = is_env_not_false("SYNCHRONOUS_KINESIS_EVENTS")
SYNCHRONOUS_DYNAMODB_EVENTS = is_env_not_false("SYNCHRONOUS_DYNAMODB_EVENTS")

# randomly inject faults to Kinesis
KINESIS_ERROR_PROBABILITY = float(os.environ.get("KINESIS_ERROR_PROBABILITY", "").strip() or 0.0)

# randomly inject faults to DynamoDB
DYNAMODB_ERROR_PROBABILITY = float(os.environ.get("DYNAMODB_ERROR_PROBABILITY", "").strip() or 0.0)
DYNAMODB_READ_ERROR_PROBABILITY = float(
    os.environ.get("DYNAMODB_READ_ERROR_PROBABILITY", "").strip() or 0.0
)
DYNAMODB_WRITE_ERROR_PROBABILITY = float(
    os.environ.get("DYNAMODB_WRITE_ERROR_PROBABILITY", "").strip() or 0.0
)

# JAVA EE heap size for dynamodb
DYNAMODB_HEAP_SIZE = os.environ.get("DYNAMODB_HEAP_SIZE", "").strip() or "256m"

# expose services on a specific host externally
HOSTNAME_EXTERNAL = os.environ.get("HOSTNAME_EXTERNAL", "").strip() or LOCALHOST

# expose SQS on a specific port externally
SQS_PORT_EXTERNAL = int(os.environ.get("SQS_PORT_EXTERNAL") or 0)

# name of the host under which the LocalStack services are available
LOCALSTACK_HOSTNAME = os.environ.get("LOCALSTACK_HOSTNAME", "").strip() or LOCALHOST

# host under which the LocalStack services are available from Lambda Docker containers
HOSTNAME_FROM_LAMBDA = os.environ.get("HOSTNAME_FROM_LAMBDA", "").strip()

# whether to remotely copy the lambda code or locally mount a volume
LAMBDA_REMOTE_DOCKER = is_env_true("LAMBDA_REMOTE_DOCKER")

# Marker name to indicate that a bucket represents the local file system. This is used for testing
# Serverless applications where we mount the Lambda code directly into the container from the host OS.
BUCKET_MARKER_LOCAL = (
    os.environ.get("BUCKET_MARKER_LOCAL", "").strip() or DEFAULT_BUCKET_MARKER_LOCAL
)

# network that the docker lambda container will be joining
LAMBDA_DOCKER_NETWORK = os.environ.get("LAMBDA_DOCKER_NETWORK", "").strip()

# custom DNS server that the docker lambda container will use
LAMBDA_DOCKER_DNS = os.environ.get("LAMBDA_DOCKER_DNS", "").strip()

# additional flags passed to Lambda Docker run/create commands
LAMBDA_DOCKER_FLAGS = os.environ.get("LAMBDA_DOCKER_FLAGS", "").strip()

# default container registry for lambda execution images
LAMBDA_CONTAINER_REGISTRY = (
    os.environ.get("LAMBDA_CONTAINER_REGISTRY", "").strip() or DEFAULT_LAMBDA_CONTAINER_REGISTRY
)

# whether to remove containers after Lambdas finished executing
LAMBDA_REMOVE_CONTAINERS = (
    os.environ.get("LAMBDA_REMOVE_CONTAINERS", "").lower().strip() not in FALSE_STRINGS
)

# directory for persisting data
DATA_DIR = os.environ.get("DATA_DIR", "").strip()

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), "localstack")

# create folders
for folder in [DATA_DIR, TMP_FOLDER]:
    if folder and not os.path.exists(folder):
        try:
            os.makedirs(folder)
        except Exception:
            # this can happen due to a race condition when starting
            # multiple processes in parallel. Should be safe to ignore
            pass

# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith("/var/folders/") and os.path.exists("/private%s" % TMP_FOLDER):
    TMP_FOLDER = "/private%s" % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set
HOST_TMP_FOLDER = os.environ.get("HOST_TMP_FOLDER", TMP_FOLDER)

# whether to enable verbose debug logging
LS_LOG = eval_log_type("LS_LOG")
DEBUG = is_env_true("DEBUG") or LS_LOG == "trace"

# whether to enable debugpy
DEVELOP = is_env_true("DEVELOP")

# PORT FOR DEBUGGER
DEVELOP_PORT = int(os.environ.get("DEVELOP_PORT", "").strip() or DEFAULT_DEVELOP_PORT)

# whether to make debugpy wait for a debbuger client
WAIT_FOR_DEBUGGER = is_env_true("WAIT_FOR_DEBUGGER")

# whether to use SSL encryption for the services
USE_SSL = is_env_true("USE_SSL")

# whether to run in TF compatibility mode for TF integration tests
# (e.g., returning verbatim ports for ELB resources, rather than edge port 4566, etc.)
TF_COMPAT_MODE = is_env_true("TF_COMPAT_MODE")

# default encoding used to convert strings to byte arrays (mainly for Python 3 compatibility)
DEFAULT_ENCODING = "utf-8"

# path to local Docker UNIX domain socket
DOCKER_SOCK = os.environ.get("DOCKER_SOCK", "").strip() or "/var/run/docker.sock"

# additional flags to pass to "docker run" when starting the stack in Docker
DOCKER_FLAGS = os.environ.get("DOCKER_FLAGS", "").strip()

# command used to run Docker containers (e.g., set to "sudo docker" to run as sudo)
DOCKER_CMD = os.environ.get("DOCKER_CMD", "").strip() or "docker"

# whether to forward edge requests in-memory (instead of via proxy servers listening on backend ports)
# TODO: this will likely become the default and may get removed in the future
FORWARD_EDGE_INMEM = True
# Default bind address for the edge service
EDGE_BIND_HOST = os.environ.get("EDGE_BIND_HOST", "").strip() or "127.0.0.1"
# port number for the edge service, the main entry point for all API invocations
EDGE_PORT = int(os.environ.get("EDGE_PORT") or 0) or DEFAULT_PORT_EDGE
# fallback port for non-SSL HTTP edge service (in case HTTPS edge service cannot be used)
EDGE_PORT_HTTP = int(os.environ.get("EDGE_PORT_HTTP") or 0)

# IP of the docker bridge used to enable access between containers
DOCKER_BRIDGE_IP = os.environ.get("DOCKER_BRIDGE_IP", "").strip()

# whether to enable API-based updates of configuration variables at runtime
ENABLE_CONFIG_UPDATES = is_env_true("ENABLE_CONFIG_UPDATES")

# CORS settings
DISABLE_CORS_CHECKS = is_env_true("DISABLE_CORS_CHECKS")
DISABLE_CUSTOM_CORS_S3 = is_env_true("DISABLE_CUSTOM_CORS_S3")
DISABLE_CUSTOM_CORS_APIGATEWAY = is_env_true("DISABLE_CUSTOM_CORS_APIGATEWAY")
EXTRA_CORS_ALLOWED_HEADERS = os.environ.get("EXTRA_CORS_ALLOWED_HEADERS", "").strip()
EXTRA_CORS_EXPOSE_HEADERS = os.environ.get("EXTRA_CORS_EXPOSE_HEADERS", "").strip()
EXTRA_CORS_ALLOWED_ORIGINS = os.environ.get("EXTRA_CORS_ALLOWED_ORIGINS", "").strip()

# whether to disable publishing events to the API
DISABLE_EVENTS = is_env_true("DISABLE_EVENTS")

# Whether to skip downloading additional infrastructure components (e.g., custom Elasticsearch versions)
SKIP_INFRA_DOWNLOADS = os.environ.get("SKIP_INFRA_DOWNLOADS", "").strip()

# Adding Stepfunctions default port
LOCAL_PORT_STEPFUNCTIONS = int(os.environ.get("LOCAL_PORT_STEPFUNCTIONS") or 8083)
# Stepfunctions lambda endpoint override
STEPFUNCTIONS_LAMBDA_ENDPOINT = os.environ.get("STEPFUNCTIONS_LAMBDA_ENDPOINT", "").strip()

# path prefix for windows volume mounting
WINDOWS_DOCKER_MOUNT_PREFIX = os.environ.get("WINDOWS_DOCKER_MOUNT_PREFIX", "/host_mnt")

# name of the main Docker container
MAIN_CONTAINER_NAME = os.environ.get("MAIN_CONTAINER_NAME", "").strip() or "localstack_main"

# the latest commit id of the repository when the docker image was created
LOCALSTACK_BUILD_GIT_HASH = os.environ.get("LOCALSTACK_BUILD_GIT_HASH", "").strip() or None

# the date on which the docker image was created
LOCALSTACK_BUILD_DATE = os.environ.get("LOCALSTACK_BUILD_DATE", "").strip() or None

# whether to skip S3 presign URL signature validation (TODO: currently enabled, until all issues are resolved)
S3_SKIP_SIGNATURE_VALIDATION = is_env_not_false("S3_SKIP_SIGNATURE_VALIDATION")

# whether to skip waiting for the infrastructure to shut down, or exit immediately
FORCE_SHUTDOWN = is_env_not_false("FORCE_SHUTDOWN")

# whether the in_docker check should always return true
OVERRIDE_IN_DOCKER = is_env_true("OVERRIDE_IN_DOCKER")


def has_docker():
    try:
        with open(os.devnull, "w") as devnull:
            subprocess.check_output("docker ps", stderr=devnull, shell=True)
        return True
    except Exception:
        return False


def is_linux():
    return platform.system() == "Linux"


# whether to use Lambda functions in a Docker container
LAMBDA_EXECUTOR = os.environ.get("LAMBDA_EXECUTOR", "").strip()
if not LAMBDA_EXECUTOR:
    LAMBDA_EXECUTOR = "docker"
    if not has_docker():
        LAMBDA_EXECUTOR = "local"

# Fallback URL to use when a non-existing Lambda is invoked. If this matches
# `dynamodb://<table_name>`, then the invocation is recorded in the corresponding
# DynamoDB table. If this matches `http(s)://...`, then the Lambda invocation is
# forwarded as a POST request to that URL.
LAMBDA_FALLBACK_URL = os.environ.get("LAMBDA_FALLBACK_URL", "").strip()
# Forward URL used to forward any Lambda invocations to an external
# endpoint (can use useful for advanced test setups)
LAMBDA_FORWARD_URL = os.environ.get("LAMBDA_FORWARD_URL", "").strip()

# A comma-delimited string of stream names and its corresponding shard count to
# initialize during startup.
# For example: "my-first-stream:1,my-other-stream:2,my-last-stream:1"
KINESIS_INITIALIZE_STREAMS = os.environ.get("KINESIS_INITIALIZE_STREAMS", "").strip()

# list of environment variable names used for configuration.
# Make sure to keep this in sync with the above!
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = [
    "SERVICES",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "LOCALSTACK_HOSTNAME",
    "LAMBDA_FALLBACK_URL",
    "LAMBDA_EXECUTOR",
    "LAMBDA_REMOTE_DOCKER",
    "LAMBDA_DOCKER_NETWORK",
    "LAMBDA_REMOVE_CONTAINERS",
    "USE_SSL",
    "DEBUG",
    "KINESIS_ERROR_PROBABILITY",
    "DYNAMODB_ERROR_PROBABILITY",
    "DYNAMODB_READ_ERROR_PROBABILITY",
    "DYNAMODB_WRITE_ERROR_PROBABILITY",
    "DOCKER_BRIDGE_IP",
    "DEFAULT_REGION",
    "LAMBDA_JAVA_OPTS",
    "LOCALSTACK_API_KEY",
    "LAMBDA_CONTAINER_REGISTRY",
    "TEST_AWS_ACCOUNT_ID",
    "DISABLE_EVENTS",
    "EDGE_PORT",
    "LS_LOG",
    "EDGE_PORT_HTTP",
    "SKIP_INFRA_DOWNLOADS",
    "STEPFUNCTIONS_LAMBDA_ENDPOINT",
    "WINDOWS_DOCKER_MOUNT_PREFIX",
    "HOSTNAME_FROM_LAMBDA",
    "LOG_LICENSE_ISSUES",
    "SYNCHRONOUS_API_GATEWAY_EVENTS",
    "SYNCHRONOUS_KINESIS_EVENTS",
    "BUCKET_MARKER_LOCAL",
    "SYNCHRONOUS_SNS_EVENTS",
    "SYNCHRONOUS_SQS_EVENTS",
    "SYNCHRONOUS_DYNAMODB_EVENTS",
    "DYNAMODB_HEAP_SIZE",
    "MAIN_CONTAINER_NAME",
    "LAMBDA_DOCKER_DNS",
    "PERSISTENCE_SINGLE_FILE",
    "S3_SKIP_SIGNATURE_VALIDATION",
    "DEVELOP",
    "DEVELOP_PORT",
    "WAIT_FOR_DEBUGGER",
    "KINESIS_INITIALIZE_STREAMS",
    "TF_COMPAT_MODE",
    "LAMBDA_DOCKER_FLAGS",
    "THUNDRA_APIKEY",
    "THUNDRA_AGENT_JAVA_VERSION",
]

for key, value in six.iteritems(DEFAULT_SERVICE_PORTS):
    clean_key = key.upper().replace("-", "_")
    CONFIG_ENV_VARS += [
        clean_key + "_BACKEND",
        clean_key + "_PORT",
        clean_key + "_PORT_EXTERNAL",
    ]


def ping(host):
    """Returns True if host responds to a ping request"""
    is_windows = platform.system().lower() == "windows"
    ping_opts = "-n 1" if is_windows else "-c 1"
    args = "ping %s %s" % (ping_opts, host)
    return (
        subprocess.call(args, shell=not is_windows, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        == 0
    )


def in_docker():
    """
    Returns True if running in a docker container, else False
    Ref. https://docs.docker.com/config/containers/runmetrics/#control-groups
    """
    if OVERRIDE_IN_DOCKER:
        return True
    if os.path.exists("/.dockerenv"):
        return True
    if not os.path.exists("/proc/1/cgroup"):
        return False
    try:
        if any(
            [
                os.path.exists("/sys/fs/cgroup/memory/docker/"),
                any(
                    [
                        "docker-" in file_names
                        for file_names in os.listdir("/sys/fs/cgroup/memory/system.slice")
                    ]
                ),
                os.path.exists("/sys/fs/cgroup/docker/"),
                any(
                    [
                        "docker-" in file_names
                        for file_names in os.listdir("/sys/fs/cgroup/system.slice/")
                    ]
                ),
            ]
        ):
            return False
    except Exception:
        pass
    with open("/proc/1/cgroup", "rt") as ifh:
        os_hostname = open("/etc/hostname", "rt").read().strip()
        content = ifh.read()
        if os_hostname in content or "docker" in content:
            return True
    return False


is_in_docker = in_docker()
is_in_linux = is_linux()

# determine IP of Docker bridge
if not DOCKER_BRIDGE_IP:
    DOCKER_BRIDGE_IP = "172.17.0.1"
    if is_in_docker:
        candidates = (DOCKER_BRIDGE_IP, "172.18.0.1")
        for ip in candidates:
            if ping(ip):
                DOCKER_BRIDGE_IP = ip
                break

# determine route to Docker host from container
try:
    DOCKER_HOST_FROM_CONTAINER = DOCKER_BRIDGE_IP
    if not is_in_docker and not is_in_linux:
        # If we're running outside docker, and would like the Lambda containers to be able
        # to access services running on the local machine, set DOCKER_HOST_FROM_CONTAINER accordingly
        if LOCALSTACK_HOSTNAME == LOCALHOST:
            DOCKER_HOST_FROM_CONTAINER = "host.docker.internal"
    # update LOCALSTACK_HOSTNAME if host.docker.internal is available
    if is_in_docker:
        DOCKER_HOST_FROM_CONTAINER = socket.gethostbyname("host.docker.internal")
        if LOCALSTACK_HOSTNAME == DOCKER_BRIDGE_IP:
            LOCALSTACK_HOSTNAME = DOCKER_HOST_FROM_CONTAINER
except socket.error:
    pass

# make sure we default to LAMBDA_REMOTE_DOCKER=true if running in Docker
if is_in_docker and not os.environ.get("LAMBDA_REMOTE_DOCKER", "").strip():
    LAMBDA_REMOTE_DOCKER = True

# local config file path in home directory
CONFIG_FILE_PATH = os.path.join(TMP_FOLDER, ".localstack")
if not is_in_docker:
    CONFIG_FILE_PATH = os.path.join(expanduser("~"), ".localstack")

# set variables no_proxy, i.e., run internal service calls directly
no_proxy = ",".join(set((LOCALSTACK_HOSTNAME, LOCALHOST, LOCALHOST_IP, "[::1]")))
if os.environ.get("no_proxy"):
    os.environ["no_proxy"] += "," + no_proxy
elif os.environ.get("NO_PROXY"):
    os.environ["NO_PROXY"] += "," + no_proxy
else:
    os.environ["no_proxy"] = no_proxy

# additional CLI commands, can be set by plugins
CLI_COMMANDS = {}

# set of valid regions
VALID_REGIONS = set(Session().get_available_regions("sns"))


def parse_service_ports():
    """Parses the environment variable $SERVICES with a comma-separated list of services
    and (optional) ports they should run on: 'service1:port1,service2,service3:port3'"""
    service_ports = os.environ.get("SERVICES", "").strip()
    if not service_ports:
        return DEFAULT_SERVICE_PORTS
    result = {}
    for service_port in re.split(r"\s*,\s*", service_ports):
        parts = re.split(r"[:=]", service_port)
        service = parts[0]
        key_upper = service.upper().replace("-", "_")
        port_env_name = "%s_PORT" % key_upper
        # (1) set default port number
        port_number = DEFAULT_SERVICE_PORTS.get(service)
        # (2) set port number from <SERVICE>_PORT environment, if present
        if os.environ.get(port_env_name):
            port_number = os.environ.get(port_env_name)
        # (3) set port number from <service>:<port> portion in $SERVICES, if present
        if len(parts) > 1:
            port_number = int(parts[-1])
        # (4) try to parse as int, fall back to 0 (invalid port)
        try:
            port_number = int(port_number)
        except Exception:
            port_number = 0
        result[service] = port_number
    return result


# TODO: we need to investigate the performance impact of this
def populate_configs(service_ports=None):
    global SERVICE_PORTS, CONFIG_ENV_VARS

    SERVICE_PORTS = service_ports or parse_service_ports()
    globs = globals()
    protocol = get_protocol()

    # define service ports and URLs as environment variables
    for key, value in six.iteritems(DEFAULT_SERVICE_PORTS):
        key_upper = key.upper().replace("-", "_")

        # define PORT_* variables with actual service ports as per configuration
        port_var_name = "PORT_%s" % key_upper
        port_number = service_port(key)
        globs[port_var_name] = port_number
        url = "%s://%s:%s" % (protocol, LOCALSTACK_HOSTNAME, port_number)
        # define TEST_*_URL variables with mock service endpoints
        url_key = "TEST_%s_URL" % key_upper
        # allow overwriting TEST_*_URL from user-defined environment variables
        existing = os.environ.get(url_key)
        url = existing or url
        # set global variable
        globs[url_key] = url
        # expose HOST_*_URL variables as environment variables
        os.environ[url_key] = url

    # expose LOCALSTACK_HOSTNAME as env. variable
    os.environ["LOCALSTACK_HOSTNAME"] = LOCALSTACK_HOSTNAME

    # create variable aliases prefixed with LOCALSTACK_ (except LOCALSTACK_HOSTNAME)
    CONFIG_ENV_VARS += [
        "LOCALSTACK_" + v for v in CONFIG_ENV_VARS if not v.startswith("LOCALSTACK_")
    ]
    CONFIG_ENV_VARS = list(set(CONFIG_ENV_VARS))


def service_port(service_key):
    if FORWARD_EDGE_INMEM:
        if service_key == "elasticsearch":
            # TODO Elasticsearch domains are a special case - we do not want to route them through
            #  the edge service, as that would require too many route mappings. In the future, we
            #  should integrate them with the port range for external services (4510-4530)
            return SERVICE_PORTS.get(service_key, 0)
        return EDGE_PORT_HTTP or EDGE_PORT
    return SERVICE_PORTS.get(service_key, 0)


def get_protocol():
    return "https" if USE_SSL else "http"


def external_service_url(service_key, host=None):
    host = host or HOSTNAME_EXTERNAL
    return "%s://%s:%s" % (get_protocol(), host, service_port(service_key))


def get_edge_url():
    port = EDGE_PORT_HTTP or EDGE_PORT
    return "%s://%s:%s" % (get_protocol(), LOCALSTACK_HOSTNAME, port)


# initialize config values
populate_configs()

# set log levels
if DEBUG:
    logging.getLogger("").setLevel(logging.DEBUG)
    logging.getLogger("localstack").setLevel(logging.DEBUG)

# whether to bundle multiple APIs into a single process, where possible
BUNDLE_API_PROCESSES = True

# whether to use a CPU/memory profiler when running the integration tests
USE_PROFILER = is_env_true("USE_PROFILER")


def load_config_file(config_file=None):
    from localstack.utils.common import get_or_create_file, to_str

    config_file = config_file or CONFIG_FILE_PATH
    content = get_or_create_file(config_file)
    try:
        configs = json.loads(to_str(content) or "{}")
    except Exception as e:
        print("Unable to load local config file %s as JSON: %s" % (config_file, e))
        return {}
    return configs


if LS_LOG == "trace":
    load_end_time = time.time()
    LOG = logging.getLogger(__name__)
    LOG.debug(
        "Initializing the configuration took %s ms" % int((load_end_time - load_start_time) * 1000)
    )
