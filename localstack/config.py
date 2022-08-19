import logging
import os
import platform
import re
import socket
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Mapping, Tuple

from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_BUCKET_MARKER_LOCAL,
    DEFAULT_DEVELOP_PORT,
    DEFAULT_LAMBDA_CONTAINER_REGISTRY,
    DEFAULT_PORT_EDGE,
    DEFAULT_SERVICE_PORTS,
    DEFAULT_VOLUME_DIR,
    ENV_INTERNAL_TEST_COLLECT_METRIC,
    ENV_INTERNAL_TEST_RUN,
    FALSE_STRINGS,
    LOCALHOST,
    LOCALHOST_IP,
    LOCALSTACK_ROOT_FOLDER,
    LOG_LEVELS,
    MODULE_MAIN_PATH,
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
        static_libs: str,
        var_libs: str,
        cache: str,
        tmp: str,
        functions: str,
        data: str,
        config: str,
        init: str,
        logs: str,
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
    def defaults() -> "Directories":
        """Returns Localstack directory paths based on the localstack filesystem hierarchy."""
        return Directories(
            static_libs="/usr/lib/localstack",
            var_libs=f"{DEFAULT_VOLUME_DIR}/lib",
            cache=f"{DEFAULT_VOLUME_DIR}/cache",
            tmp=f"{DEFAULT_VOLUME_DIR}/tmp",
            functions=f"{DEFAULT_VOLUME_DIR}/tmp",  # FIXME: remove - this was misconceived
            data=f"{DEFAULT_VOLUME_DIR}/state",
            logs=f"{DEFAULT_VOLUME_DIR}/logs",
            config="/etc/localstack/conf.d",  # for future use
            init="/etc/localstack/init",  # for future use
        )

    @staticmethod
    def for_container() -> "Directories":
        """
        Returns Localstack directory paths as they are defined within the container. Everything shared and writable
        lives in /var/lib/localstack or /tmp/localstack.

        :returns: Directories object
        """
        defaults = Directories.defaults()

        return Directories(
            static_libs=defaults.static_libs,
            var_libs=defaults.var_libs,
            cache=defaults.cache,
            tmp=defaults.tmp,
            functions=defaults.functions,
            data=defaults.data if PERSISTENCE else os.path.join(defaults.tmp, "state"),
            config=defaults.config,
            logs=defaults.logs,
            init="/docker-entrypoint-initaws.d",  # FIXME should be reworked with lifecycle hooks
        )

    @staticmethod
    def for_host() -> "Directories":
        """Return directories used for running localstack in host mode. Note that these are *not* the directories
        that are mounted into the container when the user starts localstack."""
        root = os.environ.get("FILESYSTEM_ROOT") or os.path.join(
            LOCALSTACK_ROOT_FOLDER, ".filesystem"
        )
        root = os.path.abspath(root)

        defaults = Directories.for_container()

        tmp = os.path.join(root, defaults.tmp.lstrip("/"))
        data = os.path.join(root, defaults.data.lstrip("/"))

        return Directories(
            static_libs=os.path.join(root, defaults.static_libs.lstrip("/")),
            var_libs=os.path.join(root, defaults.var_libs.lstrip("/")),
            cache=os.path.join(root, defaults.cache.lstrip("/")),
            tmp=tmp,
            functions=os.path.join(root, defaults.functions.lstrip("/")),
            data=data if PERSISTENCE else os.path.join(tmp, "state"),
            config=os.path.join(root, defaults.config.lstrip("/")),
            init=os.path.join(root, defaults.init.lstrip("/")),
            logs=os.path.join(root, defaults.logs.lstrip("/")),
        )

    @staticmethod
    def legacy_from_config():
        """Returns Localstack directory paths from the config/environment variables defined by the config."""
        # Note that the entries should be unique, as further downstream in docker_utils.py we're removing
        # duplicate host paths in the volume mounts via `dict(mount_volumes)`.

        # legacy config variables inlined
        INSTALL_DIR_INFRA = os.path.join(MODULE_MAIN_PATH, "infra")
        # ephemeral cache dir that persists across reboots
        CACHE_DIR = os.environ.get("CACHE_DIR", os.path.join(TMP_FOLDER, "cache")).strip()
        # libs cache dir that persists across reboots
        VAR_LIBS_DIR = os.environ.get("VAR_LIBS_DIR", os.path.join(TMP_FOLDER, "var_libs")).strip()

        return Directories(
            static_libs=INSTALL_DIR_INFRA,
            var_libs=VAR_LIBS_DIR,
            cache=CACHE_DIR,
            tmp=TMP_FOLDER,  # TODO: should inherit from root value for /var/lib/localstack (e.g., MOUNT_ROOT)
            functions=HOST_TMP_FOLDER,  # TODO: rename variable/consider a volume
            data=DATA_DIR,
            config=CONFIG_DIR,
            init=None,  # TODO: introduce environment variable
            logs=TMP_FOLDER,  # TODO: add variable
        )

    @staticmethod
    def legacy_for_container() -> "Directories":
        """
        Returns Localstack directory paths as they are defined within the container. Everything shared and writable
        lives in /var/lib/localstack or /tmp/localstack.

        :returns: Directories object
        """
        # only set CONTAINER_VAR_LIBS_FOLDER/CONTAINER_CACHE_FOLDER inside the container to redirect var_libs/cache to
        # another directory to avoid override by host mount
        var_libs = (
            os.environ.get("CONTAINER_VAR_LIBS_FOLDER", "").strip() or "/tmp/localstack/var_libs"
        )
        cache = os.environ.get("CONTAINER_CACHE_FOLDER", "").strip() or "/tmp/localstack/cache"
        tmp = (
            os.environ.get("CONTAINER_TMP_FOLDER", "").strip() or "/tmp/localstack"
        )  # TODO: discuss movement to /var/lib/localstack/tmp
        data_dir = os.environ.get("CONTAINER_DATA_DIR_FOLDER", "").strip() or (
            DATA_DIR if in_docker() else "/tmp/localstack_data"
        )  # TODO: move to /var/lib/localstack/data
        return Directories(
            static_libs=os.path.join(MODULE_MAIN_PATH, "infra"),
            var_libs=var_libs,
            cache=cache,
            tmp=tmp,
            functions=HOST_TMP_FOLDER,  # TODO: move to /var/lib/localstack/tmp
            data=data_dir,
            config=None,  # config directory is host-only
            logs="/tmp/localstack/logs",
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


def is_linux():
    return platform.system() == "Linux"


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


# whether the in_docker check should always return true
OVERRIDE_IN_DOCKER = is_env_true("OVERRIDE_IN_DOCKER")

is_in_docker = in_docker()
is_in_linux = is_linux()

# CLI specific: the configuration profile to load
CONFIG_PROFILE = os.environ.get("CONFIG_PROFILE", "").strip()

# CLI specific: host configuration directory
CONFIG_DIR = os.environ.get("CONFIG_DIR", os.path.expanduser("~/.localstack"))

# keep this on top to populate environment
try:
    load_environment(CONFIG_PROFILE)
except ImportError:
    # dotenv may not be available in lambdas or other environments where config is loaded
    pass

# default AWS region
if "DEFAULT_REGION" not in os.environ:
    os.environ["DEFAULT_REGION"] = os.environ.get("AWS_DEFAULT_REGION") or AWS_REGION_US_EAST_1
DEFAULT_REGION = os.environ["DEFAULT_REGION"]

# expose services on a specific host externally
HOSTNAME_EXTERNAL = os.environ.get("HOSTNAME_EXTERNAL", "").strip() or LOCALHOST

# name of the host under which the LocalStack services are available
LOCALSTACK_HOSTNAME = os.environ.get("LOCALSTACK_HOSTNAME", "").strip() or LOCALHOST

# directory for persisting data (TODO: deprecated, simply use PERSISTENCE=1)
DATA_DIR = os.environ.get("DATA_DIR", "").strip()

# whether localstack should persist service state across localstack runs
PERSISTENCE = is_env_true("PERSISTENCE")

# whether to clear config.dirs.tmp on startup and shutdown
CLEAR_TMP_FOLDER = is_env_not_false("CLEAR_TMP_FOLDER")

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), "localstack")

# this is exclusively for the CLI to configure the container mount into /var/lib/localstack
VOLUME_DIR = os.environ.get("LOCALSTACK_VOLUME_DIR", "").strip() or TMP_FOLDER

# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith("/var/folders/") and os.path.exists("/private%s" % TMP_FOLDER):
    TMP_FOLDER = "/private%s" % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set
HOST_TMP_FOLDER = os.environ.get("HOST_TMP_FOLDER", TMP_FOLDER)

# whether to use the old directory structure and mounting config
LEGACY_DIRECTORIES = is_env_true("LEGACY_DIRECTORIES")

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

# whether to use the legacy edge proxy or the newer Gateway/HandlerChain framework
LEGACY_EDGE_PROXY = is_env_true("LEGACY_EDGE_PROXY")

# Whether to report internal failures as 500 or 501 errors.
FAIL_FAST = is_env_true("FAIL_FAST")

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
DISABLE_CORS_HEADERS = is_env_true("DISABLE_CORS_HEADERS")
DISABLE_CORS_CHECKS = is_env_true("DISABLE_CORS_CHECKS")
DISABLE_CUSTOM_CORS_S3 = is_env_true("DISABLE_CUSTOM_CORS_S3")
DISABLE_CUSTOM_CORS_APIGATEWAY = is_env_true("DISABLE_CUSTOM_CORS_APIGATEWAY")
EXTRA_CORS_ALLOWED_HEADERS = os.environ.get("EXTRA_CORS_ALLOWED_HEADERS", "").strip()
EXTRA_CORS_EXPOSE_HEADERS = os.environ.get("EXTRA_CORS_EXPOSE_HEADERS", "").strip()
EXTRA_CORS_ALLOWED_ORIGINS = os.environ.get("EXTRA_CORS_ALLOWED_ORIGINS", "").strip()
DISABLE_PREFLIGHT_PROCESSING = is_env_true("DISABLE_PREFLIGHT_PROCESSING")

# whether to disable publishing events to the API
DISABLE_EVENTS = is_env_true("DISABLE_EVENTS")
DEBUG_ANALYTICS = is_env_true("DEBUG_ANALYTICS")

# whether to eagerly start services
EAGER_SERVICE_LOADING = is_env_true("EAGER_SERVICE_LOADING")

# whether to enable multi-accounts
MULTI_ACCOUNTS = is_env_true("MULTI_ACCOUNTS")

# Whether to skip downloading additional infrastructure components (e.g., custom Elasticsearch versions)
SKIP_INFRA_DOWNLOADS = os.environ.get("SKIP_INFRA_DOWNLOADS", "").strip()

# Whether to skip downloading our signed SSL cert.
SKIP_SSL_CERT_DOWNLOAD = is_env_true("SKIP_SSL_CERT_DOWNLOAD")

# name of the main Docker container
MAIN_CONTAINER_NAME = os.environ.get("MAIN_CONTAINER_NAME", "").strip() or "localstack_main"

# the latest commit id of the repository when the docker image was created
LOCALSTACK_BUILD_GIT_HASH = os.environ.get("LOCALSTACK_BUILD_GIT_HASH", "").strip() or None

# the date on which the docker image was created
LOCALSTACK_BUILD_DATE = os.environ.get("LOCALSTACK_BUILD_DATE", "").strip() or None

# Equivalent to HTTP_PROXY, but only applicable for external connections
OUTBOUND_HTTP_PROXY = os.environ.get("OUTBOUND_HTTP_PROXY", "")

# Equivalent to HTTPS_PROXY, but only applicable for external connections
OUTBOUND_HTTPS_PROXY = os.environ.get("OUTBOUND_HTTPS_PROXY", "")

# Whether to enable the partition adjustment listener (in order to support other partitions that the default)
ARN_PARTITION_REWRITING = is_env_true("ARN_PARTITION_REWRITING")

# whether to skip waiting for the infrastructure to shut down, or exit immediately
FORCE_SHUTDOWN = is_env_not_false("FORCE_SHUTDOWN")

# whether to return mocked success responses for still unimplemented API methods
MOCK_UNIMPLEMENTED = is_env_true("MOCK_UNIMPLEMENTED")

# set variables no_proxy, i.e., run internal service calls directly
no_proxy = ",".join([LOCALSTACK_HOSTNAME, LOCALHOST, LOCALHOST_IP, "[::1]"])
if os.environ.get("no_proxy"):
    os.environ["no_proxy"] += "," + no_proxy
elif os.environ.get("NO_PROXY"):
    os.environ["NO_PROXY"] += "," + no_proxy
else:
    os.environ["no_proxy"] = no_proxy

# additional CLI commands, can be set by plugins
CLI_COMMANDS = {}

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

# -----
# SERVICE-SPECIFIC CONFIGS BELOW
# -----

# port ranges for external service instances (f.e. elasticsearch clusters, opensearch clusters,...)
EXTERNAL_SERVICE_PORTS_START = int(
    os.environ.get("EXTERNAL_SERVICE_PORTS_START")
    or os.environ.get("SERVICE_INSTANCES_PORTS_START")
    or 4510
)
EXTERNAL_SERVICE_PORTS_END = int(
    os.environ.get("EXTERNAL_SERVICE_PORTS_END")
    or os.environ.get("SERVICE_INSTANCES_PORTS_END")
    or (EXTERNAL_SERVICE_PORTS_START + 50)
)

# java options to Lambda
LAMBDA_JAVA_OPTS = os.environ.get("LAMBDA_JAVA_OPTS", "").strip()

# limit in which to kinesalite will start throwing exceptions
KINESIS_SHARD_LIMIT = os.environ.get("KINESIS_SHARD_LIMIT", "").strip() or "100"

# delay in kinesalite response when making changes to streams
KINESIS_LATENCY = os.environ.get("KINESIS_LATENCY", "").strip() or "500"

# Delay between data persistence (in seconds)
KINESIS_MOCK_PERSIST_INTERVAL = os.environ.get("KINESIS_MOCK_PERSIST_INTERVAL", "").strip() or "5s"

# Kinesis provider - either "kinesis-mock" or "kinesalite"
KINESIS_PROVIDER = os.environ.get("KINESIS_PROVIDER") or "kinesis-mock"

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

# single DB instance across multiple credentials are regions
DYNAMODB_SHARE_DB = int(os.environ.get("DYNAMODB_SHARE_DB") or 0)

# Used to toggle QueueDeletedRecently errors when re-creating a queue within 60 seconds of deleting it
SQS_DELAY_RECENTLY_DELETED = is_env_true("SQS_DELAY_RECENTLY_DELETED")

# expose SQS on a specific port externally
SQS_PORT_EXTERNAL = int(os.environ.get("SQS_PORT_EXTERNAL") or 0)

# Strategy used when creating SQS queue urls. can be "off", "domain", or "path"
SQS_ENDPOINT_STRATEGY = os.environ.get("SQS_ENDPOINT_STRATEGY", "") or "off"

# host under which the LocalStack services are available from Lambda Docker containers
HOSTNAME_FROM_LAMBDA = os.environ.get("HOSTNAME_FROM_LAMBDA", "").strip()

# whether to remotely copy the Lambda code or locally mount a volume
LAMBDA_REMOTE_DOCKER = is_env_true("LAMBDA_REMOTE_DOCKER")
# make sure we default to LAMBDA_REMOTE_DOCKER=true if running in Docker
if is_in_docker and not os.environ.get("LAMBDA_REMOTE_DOCKER", "").strip():
    LAMBDA_REMOTE_DOCKER = True

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

# prebuild images before execution? Increased cold start time on the tradeoff of increased time until lambda is ACTIVE
LAMBDA_PREBUILD_IMAGES = is_env_true("LAMBDA_PREBUILD_IMAGES")

# default container registry for lambda execution images
LAMBDA_CONTAINER_REGISTRY = (
    os.environ.get("LAMBDA_CONTAINER_REGISTRY", "").strip() or DEFAULT_LAMBDA_CONTAINER_REGISTRY
)

# whether to remove containers after Lambdas finished executing
LAMBDA_REMOVE_CONTAINERS = (
    os.environ.get("LAMBDA_REMOVE_CONTAINERS", "").lower().strip() not in FALSE_STRINGS
)

# Adding Stepfunctions default port
LOCAL_PORT_STEPFUNCTIONS = int(os.environ.get("LOCAL_PORT_STEPFUNCTIONS") or 8083)
# Stepfunctions lambda endpoint override
STEPFUNCTIONS_LAMBDA_ENDPOINT = os.environ.get("STEPFUNCTIONS_LAMBDA_ENDPOINT", "").strip()

# path prefix for windows volume mounting
WINDOWS_DOCKER_MOUNT_PREFIX = os.environ.get("WINDOWS_DOCKER_MOUNT_PREFIX", "/host_mnt")

# whether to skip S3 presign URL signature validation (TODO: currently enabled, until all issues are resolved)
S3_SKIP_SIGNATURE_VALIDATION = is_env_not_false("S3_SKIP_SIGNATURE_VALIDATION")

# user-defined lambda executor mode
LAMBDA_EXECUTOR = os.environ.get("LAMBDA_EXECUTOR", "").strip()

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

# whether lambdas should use stay open mode if executed in "docker-reuse" executor
LAMBDA_STAY_OPEN_MODE = is_in_docker and is_env_not_false("LAMBDA_STAY_OPEN_MODE")

# truncate output string slices value
LAMBDA_TRUNCATE_STDOUT = int(os.getenv("LAMBDA_TRUNCATE_STDOUT") or 2000)

# A comma-delimited string of stream names and its corresponding shard count to
# initialize during startup.
# For example: "my-first-stream:1,my-other-stream:2,my-last-stream:1"
KINESIS_INITIALIZE_STREAMS = os.environ.get("KINESIS_INITIALIZE_STREAMS", "").strip()

# KMS provider - can be either "local-kms" or "moto"
KMS_PROVIDER = (os.environ.get("KMS_PROVIDER") or "").strip() or "moto"

# URL to a custom OpenSearch/Elasticsearch backend cluster. If this is set to a valid URL, then localstack will not
# create OpenSearch/Elasticsearch cluster instances, but instead forward all domains to the given backend.
OPENSEARCH_CUSTOM_BACKEND = (
    os.environ.get("OPENSEARCH_CUSTOM_BACKEND", "").strip()
    or os.environ.get("ES_CUSTOM_BACKEND", "").strip()
)

# Strategy used when creating OpenSearch/Elasticsearch domain endpoints routed through the edge proxy
# valid values: domain | path | port (off)
OPENSEARCH_ENDPOINT_STRATEGY = (
    os.environ.get("OPENSEARCH_ENDPOINT_STRATEGY", "").strip()
    or os.environ.get("ES_ENDPOINT_STRATEGY", "").strip()
    or "domain"
)
if OPENSEARCH_ENDPOINT_STRATEGY == "off":
    OPENSEARCH_ENDPOINT_STRATEGY = "port"

# Whether to start one cluster per domain (default), or multiplex opensearch domains to a single clusters
OPENSEARCH_MULTI_CLUSTER = is_env_not_false("OPENSEARCH_MULTI_CLUSTER") or is_env_true(
    "ES_MULTI_CLUSTER"
)

# list of environment variable names used for configuration.
# Make sure to keep this in sync with the above!
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = [
    "BUCKET_MARKER_LOCAL",
    "DEBUG",
    "DEFAULT_REGION",
    "DEVELOP",
    "DEVELOP_PORT",
    "DISABLE_CORS_CHECKS",
    "DISABLE_CORS_HEADERS",
    "DISABLE_CUSTOM_CORS_APIGATEWAY",
    "DISABLE_CUSTOM_CORS_S3",
    "DISABLE_EVENTS",
    "DOCKER_BRIDGE_IP",
    "DYNAMODB_ERROR_PROBABILITY",
    "DYNAMODB_HEAP_SIZE",
    "DYNAMODB_SHARE_DB",
    "DYNAMODB_READ_ERROR_PROBABILITY",
    "DYNAMODB_WRITE_ERROR_PROBABILITY",
    "EAGER_SERVICE_LOADING",
    "EDGE_BIND_HOST",
    "EDGE_FORWARD_URL",
    "EDGE_PORT",
    "EDGE_PORT_HTTP",
    "ENABLE_CONFIG_UPDATES",
    "ES_CUSTOM_BACKEND",
    "ES_ENDPOINT_STRATEGY",
    "ES_MULTI_CLUSTER",
    "EXTRA_CORS_ALLOWED_HEADERS",
    "EXTRA_CORS_ALLOWED_ORIGINS",
    "EXTRA_CORS_EXPOSE_HEADERS",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "KINESIS_ERROR_PROBABILITY",
    "KINESIS_INITIALIZE_STREAMS",
    "KINESIS_MOCK_PERSIST_INTERVAL",
    "LAMBDA_CODE_EXTRACT_TIME",
    "LAMBDA_CONTAINER_REGISTRY",
    "LAMBDA_DOCKER_DNS",
    "LAMBDA_DOCKER_FLAGS",
    "LAMBDA_DOCKER_NETWORK",
    "LAMBDA_EXECUTOR",
    "LAMBDA_FALLBACK_URL",
    "LAMBDA_FORWARD_URL",
    "LAMBDA_JAVA_OPTS",
    "LAMBDA_REMOTE_DOCKER",
    "LAMBDA_REMOVE_CONTAINERS",
    "LAMBDA_STAY_OPEN_MODE",
    "LAMBDA_TRUNCATE_STDOUT",
    "LEGACY_DIRECTORIES",
    "LEGACY_DOCKER_CLIENT",
    "LEGACY_EDGE_PROXY",
    "LOCALSTACK_API_KEY",
    "LOCALSTACK_HOSTNAME",
    "LOG_LICENSE_ISSUES",
    "LS_LOG",
    "MAIN_CONTAINER_NAME",
    "MULTI_ACCOUNTS",
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "OUTBOUND_HTTP_PROXY",
    "OUTBOUND_HTTPS_PROXY",
    "PERSISTENCE",
    "REQUESTS_CA_BUNDLE",
    "S3_SKIP_SIGNATURE_VALIDATION",
    "SERVICES",
    "SKIP_INFRA_DOWNLOADS",
    "SKIP_SSL_CERT_DOWNLOAD",
    "SQS_DELAY_RECENTLY_DELETED",
    "SQS_ENDPOINT_STRATEGY",
    "SQS_PORT_EXTERNAL",
    "STEPFUNCTIONS_LAMBDA_ENDPOINT",
    "SYNCHRONOUS_API_GATEWAY_EVENTS",
    "SYNCHRONOUS_DYNAMODB_EVENTS",
    "SYNCHRONOUS_KINESIS_EVENTS",
    "SYNCHRONOUS_SNS_EVENTS",
    "SYNCHRONOUS_SQS_EVENTS",
    "TEST_AWS_ACCOUNT_ID",
    "TEST_IAM_USER_ID",
    "TEST_IAM_USER_NAME",
    "TF_COMPAT_MODE",
    "THUNDRA_APIKEY",
    "THUNDRA_AGENT_JAVA_VERSION",
    "THUNDRA_AGENT_NODE_VERSION",
    "THUNDRA_AGENT_PYTHON_VERSION",
    "USE_SINGLE_REGION",
    "USE_SSL",
    "WAIT_FOR_DEBUGGER",
    "WINDOWS_DOCKER_MOUNT_PREFIX",
]


def is_local_test_mode() -> bool:
    """Returns True if we are running in the context of our local integration tests."""
    return is_env_true(ENV_INTERNAL_TEST_RUN)


def is_collect_metrics_mode() -> bool:
    """Returns True if metric collection is enabled."""
    return is_env_true(ENV_INTERNAL_TEST_COLLECT_METRIC)


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


def is_trace_logging_enabled():
    if LS_LOG:
        log_level = str(LS_LOG).upper()
        return log_level.lower() in TRACE_LOG_LEVELS
    return False


# set log levels immediately, but will be overwritten later by setup_logging
if DEBUG:
    logging.getLogger("").setLevel(logging.DEBUG)
    logging.getLogger("localstack").setLevel(logging.DEBUG)

LOG = logging.getLogger(__name__)
if is_trace_logging_enabled():
    load_end_time = time.time()
    LOG.debug(
        "Initializing the configuration took %s ms", int((load_end_time - load_start_time) * 1000)
    )


def parse_service_ports() -> Dict[str, int]:
    """Parses the environment variable $SERVICES with a comma-separated list of services
    and (optional) ports they should run on: 'service1:port1,service2,service3:port3'"""
    service_ports = os.environ.get("SERVICES", "").strip()
    if service_ports and not is_env_true("EAGER_SERVICE_LOADING"):
        LOG.warning("SERVICES variable is ignored if EAGER_SERVICE_LOADING=0.")
        service_ports = None  # TODO remove logic once we clear up the service ports stuff
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


# TODO: use functools cache, instead of global variable here
SERVICE_PORTS = parse_service_ports()


def populate_config_env_var_names():
    global CONFIG_ENV_VARS

    for key, value in DEFAULT_SERVICE_PORTS.items():
        clean_key = key.upper().replace("-", "_")
        CONFIG_ENV_VARS += [
            clean_key + "_BACKEND",
            clean_key + "_PORT_EXTERNAL",
            "PROVIDER_OVERRIDE_" + clean_key,
        ]

    # create variable aliases prefixed with LOCALSTACK_ (except LOCALSTACK_HOSTNAME)
    CONFIG_ENV_VARS += [
        "LOCALSTACK_" + v for v in CONFIG_ENV_VARS if not v.startswith("LOCALSTACK_")
    ]
    CONFIG_ENV_VARS = list(set(CONFIG_ENV_VARS))


# populate env var names to be passed to the container
populate_config_env_var_names()


def service_port(service_key: str, external: bool = False) -> int:
    service_key = service_key.lower()
    if external:
        if service_key == "sqs" and SQS_PORT_EXTERNAL:
            return SQS_PORT_EXTERNAL
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


def service_url(service_key, host=None, port=None):
    host = host or LOCALHOST
    port = port or service_port(service_key)
    return f"{get_protocol()}://{host}:{port}"


def external_service_url(service_key, host=None, port=None):
    host = host or HOSTNAME_EXTERNAL
    port = port or service_port(service_key, external=True)
    return service_url(service_key, host=host, port=port)


def get_edge_port_http():
    return EDGE_PORT_HTTP or EDGE_PORT


def get_edge_url(localstack_hostname=None, protocol=None):
    port = get_edge_port_http()
    protocol = protocol or get_protocol()
    localstack_hostname = localstack_hostname or LOCALSTACK_HOSTNAME
    return "%s://%s:%s" % (protocol, localstack_hostname, port)


def edge_ports_info():
    if EDGE_PORT_HTTP:
        result = "ports %s/%s" % (EDGE_PORT, EDGE_PORT_HTTP)
    else:
        result = "port %s" % EDGE_PORT
    result = "%s %s" % (get_protocol(), result)
    return result


class ServiceProviderConfig(Mapping[str, str]):
    _provider_config: Dict[str, str]
    default_value: str
    override_prefix: str = "PROVIDER_OVERRIDE_"

    def __init__(self, default_value: str):
        self._provider_config = {}
        self.default_value = default_value

    def load_from_environment(self, env: Mapping[str, str] = None):
        if env is None:
            env = os.environ
        for key, value in env.items():
            if key.startswith(self.override_prefix):
                self.set_provider(key[len(self.override_prefix) :].lower().replace("_", "-"), value)

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

SERVICE_PROVIDER_CONFIG.load_from_environment()


def init_legacy_directories() -> Directories:
    global PERSISTENCE
    from localstack import constants

    constants.DEFAULT_VOLUME_DIR = "/tmp/localstack"

    if DATA_DIR:
        PERSISTENCE = True

    if is_in_docker:
        dirs = Directories.legacy_for_container()
    else:
        dirs = Directories.legacy_from_config()

    dirs.mkdirs()
    return dirs


def init_directories() -> Directories:
    global DATA_DIR, PERSISTENCE

    if DATA_DIR:
        # deprecation path: DATA_DIR being set means persistence is activated, but we're ignoring the path set in
        # DATA_DIR
        os.environ["PERSISTENCE"] = "1"
        PERSISTENCE = True

    if is_in_docker:
        dirs = Directories.for_container()
    else:
        dirs = Directories.for_host()

    if PERSISTENCE:
        if DATA_DIR:
            LOG.warning(
                "Persistence mode was activated using the DATA_DIR variable. DATA_DIR is deprecated and "
                "its value is ignored. The data is instead stored into %s in the LocalStack volume.",
                dirs.data,
            )

        # deprecation path
        DATA_DIR = dirs.data
        os.environ["DATA_DIR"] = dirs.data  # still needed for external tools

    return dirs


# initialize directories
dirs: Directories
if LEGACY_DIRECTORIES:
    CLEAR_TMP_FOLDER = False
    dirs = init_legacy_directories()
else:
    dirs = init_directories()
