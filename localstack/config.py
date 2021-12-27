import logging
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Mapping, Tuple

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
    INSTALL_DIR_INFRA,
    LOCALHOST,
    LOCALHOST_IP,
    LOG_LEVELS,
    TRACE_LOG_LEVELS,
    TRUE_STRINGS,
)

# keep track of start time, for performance debugging
load_start_time = time.time()


class Directories:
    """
    Holds the different directories available to localstack. Some directories are shared between the host and the
    localstack container, some live only on the host and some only in the container.

    Attributes:
        static_libs: container only; binaries and libraries statically packaged with the image
        var_libs:    shared; binaries and libraries+data computed at runtime: lazy-loaded binaries, ssl cert, ...
        cache:       shared; ephemeral data that has to persist across localstack runs and reboots
        tmp:         shared; ephemeral data that has to persist across localstack runs but not reboots
        functions:   shared; volume to communicate between host<->lambda containers
        data:        shared; holds localstack state, pods, ...
        config:      host only; pre-defined configuration values, cached credentials, machine id, ...
        init:        shared; user-defined provisioning scripts executed in the container when it starts
        logs:        shared; log files produced by localstack
    """

    static_libs: str
    var_libs: str
    cache: str
    tmp: str
    functions: str
    data: str
    config: str
    init: str
    logs: str

    # these are the folders mounted into the container by default when the CLI is used
    default_bind_mounts = ["var_libs", "cache", "tmp", "data", "init", "logs"]

    def __init__(
        self,
        static_libs: str = None,
        var_libs: str = None,
        cache: str = None,
        tmp: str = None,
        functions: str = None,
        data: str = None,
        config: str = None,
        init: str = None,
        logs: str = None,
    ) -> None:
        super().__init__()
        self.static_libs = static_libs
        self.var_libs = var_libs
        self.cache = cache
        self.tmp = tmp
        self.functions = functions
        self.data = data
        self.config = config
        self.init = init
        self.logs = logs

    @staticmethod
    def from_config():
        """Returns Localstack directory paths from the config/environment variables defined by the config."""
        return Directories(
            static_libs=INSTALL_DIR_INFRA,
            var_libs=TMP_FOLDER,  # TODO: add variable
            cache=CACHE_DIR,
            tmp=TMP_FOLDER,  # TODO: should inherit from root value for /var/lib/localstack (e.g., MOUNT_ROOT)
            functions=HOST_TMP_FOLDER,  # TODO: rename variable/consider a volume
            data=DATA_DIR,
            config=CONFIG_DIR,
            init=None,  # TODO: introduce environment variable
            logs=TMP_FOLDER,  # TODO: add variable
        )

    @staticmethod
    def for_container() -> "Directories":
        """
        Returns Localstack directory paths as they are defined within the container. Everything shared and writable
        lives in /var/lib/localstack or /tmp/localstack.

        :returns: Directories object
        """
        # only set CONTAINER_VAR_LIBS_FOLDER/CONTAINER_CACHE_FOLDER inside the container to redirect var_libs/cache to
        # another directory to avoid override by host mount
        var_libs = (
            os.environ.get("CONTAINER_VAR_LIBS_FOLDER", "").strip()
            or "/var/lib/localstack/var_libs"
        )
        cache = os.environ.get("CONTAINER_CACHE_FOLDER", "").strip() or "/var/lib/localstack/cache"
        return Directories(
            static_libs=INSTALL_DIR_INFRA,
            var_libs=var_libs,
            cache=cache,
            tmp=TMP_FOLDER,  # TODO: move to /var/lib/localstack/tmp - or /tmp/localstack
            functions=HOST_TMP_FOLDER,  # TODO: move to /var/lib/localstack/tmp
            data=DATA_DIR,  # TODO: move to /var/lib/localstack/data
            config=None,  # config directory is host-only
            logs="/var/lib/localstack/logs",
            init="/docker-entrypoint-initaws.d",
        )

    def mkdirs(self):
        for folder in [
            self.static_libs,
            self.var_libs,
            self.cache,
            self.tmp,
            self.functions,
            self.data,
            self.config,
            self.init,
            self.logs,
        ]:
            if folder and not os.path.exists(folder):
                try:
                    os.makedirs(folder)
                except Exception:
                    # this can happen due to a race condition when starting
                    # multiple processes in parallel. Should be safe to ignore
                    pass

    def __str__(self):
        return str(self.__dict__)


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


def load_environment(profile: str = None):
    """Loads the environment variables from ~/.localstack/{profile}.env
    :param profile: the profile to load (defaults to "default")
    """
    if not profile:
        profile = "default"

    path = os.path.join(CONFIG_DIR, f"{profile}.env")
    if not os.path.exists(path):
        return

    import dotenv

    dotenv.load_dotenv(path, override=False)


# the configuration profile to load
CONFIG_PROFILE = os.environ.get("CONFIG_PROFILE", "").strip()

# host configuration directory
CONFIG_DIR = os.environ.get("CONFIG_DIR", os.path.expanduser("~/.localstack"))

# keep this on top to populate environment
try:
    load_environment(CONFIG_PROFILE)
except ImportError:
    # dotenv may not be available in lambdas or other environments where config is loaded
    pass

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

# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith("/var/folders/") and os.path.exists("/private%s" % TMP_FOLDER):
    TMP_FOLDER = "/private%s" % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set
HOST_TMP_FOLDER = os.environ.get("HOST_TMP_FOLDER", TMP_FOLDER)

# ephemeral cache dir that persists over reboots
CACHE_DIR = os.environ.get("CACHE_DIR", os.path.join(TMP_FOLDER, "cache")).strip()

# whether to enable verbose debug logging
LS_LOG = eval_log_type("LS_LOG")
DEBUG = is_env_true("DEBUG") or LS_LOG in TRACE_LOG_LEVELS

# whether to enable debugpy
DEVELOP = is_env_true("DEVELOP")

# PORT FOR DEBUGGER
DEVELOP_PORT = int(os.environ.get("DEVELOP_PORT", "").strip() or DEFAULT_DEVELOP_PORT)

# whether to make debugpy wait for a debbuger client
WAIT_FOR_DEBUGGER = is_env_true("WAIT_FOR_DEBUGGER")

# whether to use SSL encryption for the services
# TODO: this is deprecated and should be removed (edge port supports HTTP/HTTPS multiplexing)
USE_SSL = is_env_true("USE_SSL")

# whether to use the legacy single-region mode, defined via DEFAULT_REGION
USE_SINGLE_REGION = is_env_true("USE_SINGLE_REGION")

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

# use the command line docker client instead of the new sdk version, might get removed in the future
LEGACY_DOCKER_CLIENT = is_env_true("LEGACY_DOCKER_CLIENT")

# whether to forward edge requests in-memory (instead of via proxy servers listening on backend ports)
# TODO: this will likely become the default and may get removed in the future
FORWARD_EDGE_INMEM = True
# Default bind address for the edge service
EDGE_BIND_HOST = os.environ.get("EDGE_BIND_HOST", "").strip() or "127.0.0.1"
# port number for the edge service, the main entry point for all API invocations
EDGE_PORT = int(os.environ.get("EDGE_PORT") or 0) or DEFAULT_PORT_EDGE
# fallback port for non-SSL HTTP edge service (in case HTTPS edge service cannot be used)
EDGE_PORT_HTTP = int(os.environ.get("EDGE_PORT_HTTP") or 0)
# optional target URL to forward all edge requests to
EDGE_FORWARD_URL = os.environ.get("EDGE_FORWARD_URL", "").strip()

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
DEBUG_ANALYTICS = is_env_true("DEBUG_ANALYTICS")

# whether to eagerly start services
EAGER_SERVICE_LOADING = is_env_true("EAGER_SERVICE_LOADING")

# Whether to skip downloading additional infrastructure components (e.g., custom Elasticsearch versions)
SKIP_INFRA_DOWNLOADS = os.environ.get("SKIP_INFRA_DOWNLOADS", "").strip()

# whether to enable legacy record&replay persistence mechanism (default true, but will be disabled in a future release!)
LEGACY_PERSISTENCE = is_env_not_false("LEGACY_PERSISTENCE")

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

# whether to return mocked success responses for still unimplemented API methods
MOCK_UNIMPLEMENTED = is_env_true("MOCK_UNIMPLEMENTED")


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
# Time in seconds to wait at max while extracting Lambda code.
# By default, it is 25 seconds for limiting the execution time
# to avoid client/network timeout issues
LAMBDA_CODE_EXTRACT_TIME = int(os.environ.get("LAMBDA_CODE_EXTRACT_TIME") or 25)

# A comma-delimited string of stream names and its corresponding shard count to
# initialize during startup.
# For example: "my-first-stream:1,my-other-stream:2,my-last-stream:1"
KINESIS_INITIALIZE_STREAMS = os.environ.get("KINESIS_INITIALIZE_STREAMS", "").strip()

# URL to a custom elasticsearch backend cluster. If this is set to a valid URL, then localstack will not create
# elasticsearch cluster instances, but instead forward all domains to the given backend.
ES_CUSTOM_BACKEND = os.environ.get("ES_CUSTOM_BACKEND", "").strip()

# Strategy used when creating elasticsearch domain endpoints routed through the edge proxy
# valid values: domain | path | off
ES_ENDPOINT_STRATEGY = os.environ.get("ES_ENDPOINT_STRATEGY", "").strip() or "domain"

# Whether to start one cluster per domain (default), or multiplex domains to a single clusters
ES_MULTI_CLUSTER = is_env_not_false("ES_MULTI_CLUSTER")

# Equivalent to HTTP_PROXY, but only applicable for external connections
OUTBOUND_HTTP_PROXY = os.environ.get("OUTBOUND_HTTP_PROXY", "")

# Equivalent to HTTPS_PROXY, but only applicable for external connections
OUTBOUND_HTTPS_PROXY = os.environ.get("OUTBOUND_HTTPS_PROXY", "")

# Whether to enable the partition adjustment listener (in order to support other partitions that the default)
ARN_PARTITION_REWRITING = is_env_true("ARN_PARTITION_REWRITING")

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
    "USE_SINGLE_REGION",
    "DEBUG",
    "KINESIS_ERROR_PROBABILITY",
    "DYNAMODB_ERROR_PROBABILITY",
    "DYNAMODB_READ_ERROR_PROBABILITY",
    "DYNAMODB_WRITE_ERROR_PROBABILITY",
    "ES_CUSTOM_BACKEND",
    "ES_ENDPOINT_STRATEGY",
    "ES_MULTI_CLUSTER",
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
    "EDGE_FORWARD_URL",
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
    "LAMBDA_FORWARD_URL",
    "LAMBDA_CODE_EXTRACT_TIME",
    "THUNDRA_APIKEY",
    "THUNDRA_AGENT_JAVA_VERSION",
    "THUNDRA_AGENT_NODE_VERSION",
    "THUNDRA_AGENT_PYTHON_VERSION",
    "DISABLE_CORS_CHECKS",
    "DISABLE_CUSTOM_CORS_S3",
    "DISABLE_CUSTOM_CORS_APIGATEWAY",
    "EXTRA_CORS_ALLOWED_HEADERS",
    "EXTRA_CORS_EXPOSE_HEADERS",
    "EXTRA_CORS_ALLOWED_ORIGINS",
    "ENABLE_CONFIG_UPDATES",
    "LOCALSTACK_HTTP_PROXY",
    "LOCALSTACK_HTTPS_PROXY",
    "REQUESTS_CA_BUNDLE",
    "LEGACY_DOCKER_CLIENT",
    "EAGER_SERVICE_LOADING",
    "LAMBDA_STAY_OPEN_MODE",
]

for key, value in six.iteritems(DEFAULT_SERVICE_PORTS):
    clean_key = key.upper().replace("-", "_")
    CONFIG_ENV_VARS += [
        clean_key + "_BACKEND",
        clean_key + "_PORT",
        clean_key + "_PORT_EXTERNAL",
        "PROVIDER_OVERRIDE_" + clean_key,
    ]


def collect_config_items() -> List[Tuple[str, Any]]:
    """Returns a list of key-value tuples of LocalStack configuration values."""
    none = object()  # sentinel object

    # collect which keys to print
    keys = []
    keys.extend(CONFIG_ENV_VARS)
    keys.append("DATA_DIR")
    keys.sort()

    values = globals()

    result = []
    for k in keys:
        v = values.get(k, none)
        if v is none:
            continue
        result.append((k, v))
    result.sort()
    return result


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

    # details: https://github.com/localstack/localstack/pull/4352
    if os.path.exists("/.dockerenv"):
        return True
    if os.path.exists("/run/.containerenv"):
        return True

    if not os.path.exists("/proc/1/cgroup"):
        return False
    try:
        if any(
            [
                os.path.exists("/sys/fs/cgroup/memory/docker/"),
                any(
                    "docker-" in file_names
                    for file_names in os.listdir("/sys/fs/cgroup/memory/system.slice")
                ),
                os.path.exists("/sys/fs/cgroup/docker/"),
                any(
                    "docker-" in file_names
                    for file_names in os.listdir("/sys/fs/cgroup/system.slice/")
                ),
            ]
        ):
            return False
    except Exception:
        pass
    with open("/proc/1/cgroup", "rt") as ifh:
        content = ifh.read()
        if "docker" in content:
            return True
        os_hostname = socket.gethostname()
        if os_hostname and os_hostname in content:
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

# whether lambdas should use stay open mode if executed in "docker-reuse" executor
LAMBDA_STAY_OPEN_MODE = is_in_docker and is_env_not_false("LAMBDA_STAY_OPEN_MODE")

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
VALID_PARTITIONS = set(Session().get_available_partitions())
VALID_REGIONS = set()
for partition in VALID_PARTITIONS:
    for region in Session().get_available_regions("sns", partition):
        VALID_REGIONS.add(region)


def parse_service_ports() -> Dict[str, int]:
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
        return get_edge_port_http()
    return SERVICE_PORTS.get(service_key, 0)


def get_protocol():
    return "https" if USE_SSL else "http"


def external_service_url(service_key, host=None):
    host = host or HOSTNAME_EXTERNAL
    return "%s://%s:%s" % (get_protocol(), host, service_port(service_key))


def get_edge_port_http():
    return EDGE_PORT_HTTP or EDGE_PORT


def get_edge_url(localstack_hostname=None, protocol=None):
    port = get_edge_port_http()
    protocol = protocol or get_protocol()
    localstack_hostname = localstack_hostname or LOCALSTACK_HOSTNAME
    return "%s://%s:%s" % (protocol, localstack_hostname, port)


# initialize config values
populate_configs()

# set log levels
if DEBUG:
    logging.getLogger("").setLevel(logging.DEBUG)
    logging.getLogger("localstack").setLevel(logging.DEBUG)

if LS_LOG in TRACE_LOG_LEVELS:
    load_end_time = time.time()
    LOG = logging.getLogger(__name__)
    LOG.debug(
        "Initializing the configuration took %s ms", int((load_end_time - load_start_time) * 1000)
    )


class ServiceProviderConfig(Mapping[str, str]):
    _provider_config: Dict[str, str]
    default_value: str

    def __init__(self, default_value: str):
        self._provider_config = {}
        self.default_value = default_value

    def get_provider(self, service: str) -> str:
        return self._provider_config.get(service, self.default_value)

    def set_provider_if_not_exists(self, service: str, provider: str) -> None:
        if service not in self._provider_config:
            self._provider_config[service] = provider

    def set_provider(self, service: str, provider: str):
        self._provider_config[service] = provider

    def bulk_set_provider_if_not_exists(self, services: List[str], provider: str):
        for service in services:
            self.set_provider_if_not_exists(service, provider)

    def __getitem__(self, item):
        return self.get_provider(item)

    def __setitem__(self, key, value):
        self.set_provider(key, value)

    def __len__(self):
        return len(self._provider_config)

    def __iter__(self):
        return self._provider_config.__iter__()


SERVICE_PROVIDER_CONFIG = ServiceProviderConfig("default")

for key, value in os.environ.items():
    if key.startswith("PROVIDER_OVERRIDE_"):
        SERVICE_PROVIDER_CONFIG.set_provider(
            key.lstrip("PROVIDER_OVERRIDE_").lower().replace("_", "-"), value
        )

# initialize directories
if is_in_docker:
    dirs = Directories.for_container()
else:
    dirs = Directories.from_config()

dirs.mkdirs()

# TODO: remove deprecation warning with next release
for path in [dirs.config, os.path.join(dirs.tmp, ".localstack")]:
    if path and os.path.isfile(path):
        print(
            f"warning: the config file .localstack is deprecated and no longer used, "
            f"please remove it by running rm {path}"
        )
