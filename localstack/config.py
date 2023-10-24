import logging
import os
import platform
import socket
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Mapping, Optional, Tuple, TypeVar, Union

from localstack import constants
from localstack.constants import (
    AWS_REGION_US_EAST_1,
    DEFAULT_BUCKET_MARKER_LOCAL,
    DEFAULT_DEVELOP_PORT,
    DEFAULT_LAMBDA_CONTAINER_REGISTRY,
    DEFAULT_VOLUME_DIR,
    ENV_INTERNAL_TEST_COLLECT_METRIC,
    ENV_INTERNAL_TEST_RUN,
    FALSE_STRINGS,
    LOCALHOST,
    LOCALHOST_IP,
    LOCALSTACK_ROOT_FOLDER,
    LOG_LEVELS,
    TRACE_LOG_LEVELS,
    TRUE_STRINGS,
)

T = TypeVar("T", str, int)

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
            init="/etc/localstack/init",
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
            init=defaults.init,
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
    def for_cli() -> "Directories":
        """Returns directories used for when running localstack CLI commands from the host system. Unlike
        ``for_container``, these here need to be cross-platform. Ideally, this should not be needed at all,
        because the localstack runtime and CLI do not share any control paths. There are a handful of
        situations where directories or files may be created lazily for CLI commands. Some paths are
        intentionally set to None to provoke errors if these paths are used from the CLI - which they
        shouldn't. This is a symptom of not having a clear separation between CLI/runtime code, which will
        be a future project."""
        import tempfile

        from localstack.utils import files

        tmp_dir = os.path.join(tempfile.gettempdir(), "localstack-cli")
        cache_dir = (files.get_user_cache_dir()).absolute() / "localstack-cli"

        return Directories(
            static_libs=None,
            var_libs=None,
            cache=str(cache_dir),  # used by analytics metadata
            tmp=tmp_dir,
            functions=None,
            data=os.path.join(tmp_dir, "state"),  # used by localstack_ext config TODO: remove
            logs=os.path.join(tmp_dir, "logs"),  # used for container logs
            config=None,  # in the context of the CLI, config.CONFIG_DIR should be used
            init=None,
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


def eval_log_type(env_var_name: str) -> Union[str, bool]:
    """Get the log type from environment variable"""
    ls_log = os.environ.get(env_var_name, "").lower().strip()
    return ls_log if ls_log in LOG_LEVELS else False


def parse_boolean_env(env_var_name: str) -> Optional[bool]:
    """Parse the value of the given env variable and return True/False, or None if it is not a boolean value."""
    value = os.environ.get(env_var_name, "").lower().strip()
    if value in TRUE_STRINGS:
        return True
    if value in FALSE_STRINGS:
        return False
    return None


def is_env_true(env_var_name: str) -> bool:
    """Whether the given environment variable has a truthy value."""
    return os.environ.get(env_var_name, "").lower().strip() in TRUE_STRINGS


def is_env_not_false(env_var_name: str) -> bool:
    """Whether the given environment variable is empty or has a truthy value."""
    return os.environ.get(env_var_name, "").lower().strip() not in FALSE_STRINGS


def load_environment(profile: str = None) -> Optional[str]:
    """Loads the environment variables from ~/.localstack/{profile}.env
    :param profile: the profile to load (defaults to "default")
    :returns str: the name of the actually loaded profile (might be the fallback)
    """
    if not profile:
        profile = "default"

    path = os.path.join(CONFIG_DIR, f"{profile}.env")
    if not os.path.exists(path):
        return None

    import dotenv

    dotenv.load_dotenv(path, override=False)
    return profile


def is_persistence_enabled() -> bool:
    return PERSISTENCE and dirs.data


def is_linux() -> bool:
    return platform.system() == "Linux"


def ping(host):
    """Returns True if host responds to a ping request"""
    is_windows = platform.system().lower() == "windows"
    ping_opts = "-n 1 -w 2000" if is_windows else "-c 1 -W 2"
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
    if OVERRIDE_IN_DOCKER is not None:
        return OVERRIDE_IN_DOCKER

    # check some marker files that we create in our Dockerfiles
    for path in [
        "/usr/lib/localstack/.community-version",
        "/usr/lib/localstack/.pro-version",
        "/tmp/localstack/.marker",
    ]:
        if os.path.isfile(path):
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
        if "docker" in content or "buildkit" in content:
            return True
        os_hostname = socket.gethostname()
        if os_hostname and os_hostname in content:
            return True

    # containerd does not set any specific file or config, but does use
    # io.containerd.snapshotter.v1.overlayfs as the overlay filesystem for `/`.
    try:
        with open("/proc/mounts", "rt") as infile:
            for line in infile:
                line = line.strip()

                if not line:
                    continue

                # skip comments
                if line[0] == "#":
                    continue

                # format (man 5 fstab)
                # <spec> <mount point> <type> <options> <rest>...
                parts = line.split()
                if len(parts) < 4:
                    # badly formatted line
                    continue

                mount_point = parts[1]
                options = parts[3]

                # only consider the root filesystem
                if mount_point != "/":
                    continue

                if "io.containerd" in options:
                    return True

    except FileNotFoundError:
        pass

    return False


# whether the in_docker check should always return True or False
OVERRIDE_IN_DOCKER = parse_boolean_env("OVERRIDE_IN_DOCKER")

is_in_docker = in_docker()
is_in_linux = is_linux()
default_ip = "0.0.0.0" if is_in_docker else "127.0.0.1"

# CLI specific: the configuration profile to load
CONFIG_PROFILE = os.environ.get("CONFIG_PROFILE", "").strip()

# CLI specific: host configuration directory
CONFIG_DIR = os.environ.get("CONFIG_DIR", os.path.expanduser("~/.localstack"))

# keep this on top to populate environment
try:
    # CLI specific: the actually loaded configuration profile
    LOADED_PROFILE = load_environment(CONFIG_PROFILE)
except ImportError:
    # dotenv may not be available in lambdas or other environments where config is loaded
    LOADED_PROFILE = None

# default AWS region (DEPRECATED!)
DEFAULT_REGION = (
    os.environ.get("DEFAULT_REGION") or os.environ.get("AWS_DEFAULT_REGION") or AWS_REGION_US_EAST_1
)

# directory for persisting data (TODO: deprecated, simply use PERSISTENCE=1)
DATA_DIR = os.environ.get("DATA_DIR", "").strip()

# whether localstack should persist service state across localstack runs
PERSISTENCE = is_env_true("PERSISTENCE")

# the strategy for loading snapshots from disk when `PERSISTENCE=1` is used (on_startup, on_request, manual)
SNAPSHOT_LOAD_STRATEGY = os.environ.get("SNAPSHOT_LOAD_STRATEGY", "").upper()

# the strategy saving snapshots to disk when `PERSISTENCE=1` is used (on_shutdown, on_request, scheduled, manual)
SNAPSHOT_SAVE_STRATEGY = os.environ.get("SNAPSHOT_SAVE_STRATEGY", "").upper()

# the flush interval (in seconds) for persistence when the snapshot save strategy is set to "scheduled"
SNAPSHOT_FLUSH_INTERVAL = int(os.environ.get("SNAPSHOT_FLUSH_INTERVAL") or 15)

# whether to clear config.dirs.tmp on startup and shutdown
CLEAR_TMP_FOLDER = is_env_not_false("CLEAR_TMP_FOLDER")

# folder for temporary files and data
TMP_FOLDER = os.path.join(tempfile.gettempdir(), "localstack")

# this is exclusively for the CLI to configure the container mount into /var/lib/localstack
VOLUME_DIR = os.environ.get("LOCALSTACK_VOLUME_DIR", "").strip() or TMP_FOLDER

# fix for Mac OS, to be able to mount /var/folders in Docker
if TMP_FOLDER.startswith("/var/folders/") and os.path.exists("/private%s" % TMP_FOLDER):
    TMP_FOLDER = "/private%s" % TMP_FOLDER

# temporary folder of the host (required when running in Docker). Fall back to local tmp folder if not set. (DEPRECATED!)
HOST_TMP_FOLDER = os.environ.get("HOST_TMP_FOLDER", TMP_FOLDER)

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

# whether legacy s3 is enabled
LEGACY_S3_PROVIDER = os.environ.get("PROVIDER_OVERRIDE_S3", "") == "legacy"

# whether the S3 native provider is enabled
NATIVE_S3_PROVIDER = os.environ.get("PROVIDER_OVERRIDE_S3", "") in ("v3", "stream")

# Whether to report internal failures as 500 or 501 errors.
FAIL_FAST = is_env_true("FAIL_FAST")

# whether to use the legacy single-region mode, defined via DEFAULT_REGION (DEPRECATED!)
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

# Docker image to use when starting up containers for port checks
PORTS_CHECK_DOCKER_IMAGE = os.environ.get("PORTS_CHECK_DOCKER_IMAGE", "").strip()

# whether to forward edge requests in-memory (instead of via proxy servers listening on backend ports)
# TODO: this will likely become the default and may get removed in the future
FORWARD_EDGE_INMEM = True


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

# expose services on a specific host externally
# DEPRECATED:  since v2.0.0 as we are moving to LOCALSTACK_HOST
HOSTNAME_EXTERNAL = os.environ.get("HOSTNAME_EXTERNAL", "").strip() or LOCALHOST

# name of the host under which the LocalStack services are available
# DEPRECATED: if the user sets this since v2.0.0 as we are moving to LOCALSTACK_HOST
LOCALSTACK_HOSTNAME = os.environ.get("LOCALSTACK_HOSTNAME", "").strip() or LOCALHOST


class HostAndPort:
    """
    Definition of an address for a server to listen to.

    Includes a `parse` method to convert from `str`, allowing for default fallbacks, as well as
    some helper methods to help tests - particularly testing for equality and a hash function
    so that `HostAndPort` instances can be used as keys to dictionaries.
    """

    host: str
    port: int

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port

    @classmethod
    def parse(
        cls,
        input: str,
        default_host: str,
        default_port: int,
    ) -> "HostAndPort":
        """
        Parse a `HostAndPort` from strings like:
            - 0.0.0.0:4566 -> host=0.0.0.0, port=4566
            - 0.0.0.0      -> host=0.0.0.0, port=`default_port`
            - :4566        -> host=`default_host`, port=4566
        """
        host, port = default_host, default_port
        if ":" in input:
            hostname, port_s = input.split(":", 1)
            if hostname.strip():
                host = hostname.strip()
            try:
                port = int(port_s)
            except ValueError as e:
                raise ValueError(f"specified port {port_s} not a number") from e
        else:
            if input.strip():
                host = input.strip()

        # validation
        if port < 0 or port >= 2**16:
            raise ValueError("port out of range")

        return cls(host=host, port=port)

    def _get_unprivileged_port_range_start(self) -> int:
        try:
            with open(
                "/proc/sys/net/ipv4/ip_unprivileged_port_start", "rt"
            ) as unprivileged_port_start:
                port = unprivileged_port_start.read()
                return int(port.strip())
        except Exception:
            return 1024

    def is_unprivileged(self) -> bool:
        return self.port >= self._get_unprivileged_port_range_start()

    def __hash__(self) -> int:
        return hash((self.host, self.port))

    # easier tests
    def __eq__(self, other: "str | HostAndPort") -> bool:
        if isinstance(other, self.__class__):
            return self.host == other.host and self.port == other.port
        elif isinstance(other, str):
            return str(self) == other
        else:
            raise TypeError(f"cannot compare {self.__class__} to {other.__class__}")

    def __str__(self) -> str:
        return f"{self.host}:{self.port}" if self.port is not None else self.host

    def __repr__(self) -> str:
        return f"HostAndPort(host={self.host}, port={self.port})"


class UniqueHostAndPortList(List[HostAndPort]):
    """
    Container type that ensures that ports added to the list are unique based
    on these rules:
        - 0.0.0.0 "trumps" any other binding, i.e. adding 127.0.0.1:4566 to
          [0.0.0.0:4566] is a no-op
        - adding identical hosts and ports is a no-op
        - adding `0.0.0.0:4566` to [`127.0.0.1:4566`] "upgrades" the binding to
          create [`0.0.0.0:4566`]
    """

    def __init__(self, iterable=None):
        super().__init__()
        for item in iterable or []:
            self.append(item)

    def append(self, value: HostAndPort):
        # no exact duplicates
        if value in self:
            return

        # if 0.0.0.0:<port> already exists in the list, then do not add the new
        # item
        for item in self:
            if item.host == "0.0.0.0" and item.port == value.port:
                return

        # if we add 0.0.0.0:<port> and already contain *:<port> then bind on
        # 0.0.0.0
        contained_ports = set(every.port for every in self)
        if value.host == "0.0.0.0" and value.port in contained_ports:
            for item in self:
                if item.port == value.port:
                    item.host = value.host
            return

        # append the item
        super().append(value)


def populate_legacy_edge_configuration(
    environment: Mapping[str, str]
) -> Tuple[HostAndPort, UniqueHostAndPortList, str, int, int]:
    localstack_host_raw = environment.get("LOCALSTACK_HOST")
    gateway_listen_raw = environment.get("GATEWAY_LISTEN")

    # new for v2
    # populate LOCALSTACK_HOST first since GATEWAY_LISTEN may be derived from LOCALSTACK_HOST
    localstack_host = localstack_host_raw
    if localstack_host is None:
        localstack_host = HostAndPort(
            host=constants.LOCALHOST_HOSTNAME, port=constants.DEFAULT_PORT_EDGE
        )
    else:
        localstack_host = HostAndPort.parse(
            localstack_host,
            default_host=constants.LOCALHOST_HOSTNAME,
            default_port=constants.DEFAULT_PORT_EDGE,
        )

    def legacy_fallback(envar_name: str, default: T) -> T:
        result = default
        result_raw = environment.get(envar_name)
        if result_raw is not None and gateway_listen_raw is None:
            result = result_raw

        return result

    # parse gateway listen from multiple components
    if gateway_listen_raw is not None:
        gateway_listen = []
        for address in gateway_listen_raw.split(","):
            gateway_listen.append(
                HostAndPort.parse(
                    address.strip(),
                    default_host=default_ip,
                    default_port=localstack_host.port,
                )
            )
    else:
        edge_port = int(environment.get("EDGE_PORT", localstack_host.port))
        edge_port_http = int(environment.get("EDGE_PORT_HTTP", 0))
        gateway_listen = [HostAndPort(host=default_ip, port=edge_port)]
        if edge_port_http:
            gateway_listen.append(HostAndPort(host=default_ip, port=edge_port_http))

    assert gateway_listen is not None
    assert localstack_host is not None

    # derive legacy variables from GATEWAY_LISTEN unless GATEWAY_LISTEN is not given and
    # legacy variables are
    edge_bind_host = legacy_fallback("EDGE_BIND_HOST", gateway_listen[0].host)
    edge_port = int(legacy_fallback("EDGE_PORT", gateway_listen[0].port))
    edge_port_http = int(
        legacy_fallback("EDGE_PORT_HTTP", 0),
    )

    return (
        localstack_host,
        UniqueHostAndPortList(gateway_listen),
        edge_bind_host,
        edge_port,
        edge_port_http,
    )


# How to access LocalStack
GATEWAY_LISTEN: List[HostAndPort]
(
    # -- Cosmetic
    LOCALSTACK_HOST,
    # -- Edge configuration
    # Main configuration of the listen address of the hypercorn proxy. Of the form
    # <ip_address>:<port>(,<ip_address>:port>)*
    GATEWAY_LISTEN,
    # -- Legacy variables
    EDGE_BIND_HOST,
    EDGE_PORT,
    EDGE_PORT_HTTP,
) = populate_legacy_edge_configuration(os.environ)

# optional target URL to forward all edge requests to
EDGE_FORWARD_URL = os.environ.get("EDGE_FORWARD_URL", "").strip()

# IP of the docker bridge used to enable access between containers
DOCKER_BRIDGE_IP = os.environ.get("DOCKER_BRIDGE_IP", "").strip()

# Default timeout for Docker API calls sent by the Docker SDK client, in seconds.
DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS = int(os.environ.get("DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS") or 60)

# Default number of retries to connect to the Docker API by the Docker SDK client.
DOCKER_SDK_DEFAULT_RETRIES = int(os.environ.get("DOCKER_SDK_DEFAULT_RETRIES") or 0)

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

# whether to log fine-grained debugging information for the handler chain
DEBUG_HANDLER_CHAIN = is_env_true("DEBUG_HANDLER_CHAIN")

# whether to eagerly start services
EAGER_SERVICE_LOADING = is_env_true("EAGER_SERVICE_LOADING")

# Whether to skip downloading additional infrastructure components (e.g., custom Elasticsearch versions)
SKIP_INFRA_DOWNLOADS = os.environ.get("SKIP_INFRA_DOWNLOADS", "").strip()

# Whether to skip downloading our signed SSL cert.
SKIP_SSL_CERT_DOWNLOAD = is_env_true("SKIP_SSL_CERT_DOWNLOAD")

# Absolute path to a custom certificate (pem file)
CUSTOM_SSL_CERT_PATH = os.environ.get("CUSTOM_SSL_CERT_PATH", "").strip()

# Allow non-standard AWS regions
ALLOW_NONSTANDARD_REGIONS = is_env_true("ALLOW_NONSTANDARD_REGIONS")
if ALLOW_NONSTANDARD_REGIONS:
    os.environ["MOTO_ALLOW_NONEXISTENT_REGION"] = "true"

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
no_proxy = ",".join([constants.LOCALHOST_HOSTNAME, LOCALHOST, LOCALHOST_IP, "[::1]"])
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
            # TODO: remove from here - should not perform I/O operations in top-level config.py
            if ping(ip):
                DOCKER_BRIDGE_IP = ip
                break

# AWS account used to store internal resources such as Lambda archives or internal SQS queues.
# It should not be modified by the user, or visible to him, except as through a presigned url with the
# get-function call.
INTERNAL_RESOURCE_ACCOUNT = os.environ.get("INTERNAL_RESOURCE_ACCOUNT") or "949334387222"

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

# PUBLIC v1: -Xmx512M (example) Currently not supported in new provider but possible via custom entrypoint.
# Allow passing custom JVM options to Java Lambdas executed in Docker.
LAMBDA_JAVA_OPTS = os.environ.get("LAMBDA_JAVA_OPTS", "").strip()

# limit in which to kinesis-mock will start throwing exceptions
KINESIS_SHARD_LIMIT = os.environ.get("KINESIS_SHARD_LIMIT", "").strip() or "100"

# limit in which to kinesis-mock will start throwing exceptions
KINESIS_ON_DEMAND_STREAM_COUNT_LIMIT = (
    os.environ.get("KINESIS_ON_DEMAND_STREAM_COUNT_LIMIT", "").strip() or "10"
)

# delay in kinesis-mock response when making changes to streams
KINESIS_LATENCY = os.environ.get("KINESIS_LATENCY", "").strip() or "500"

# Delay between data persistence (in seconds)
KINESIS_MOCK_PERSIST_INTERVAL = os.environ.get("KINESIS_MOCK_PERSIST_INTERVAL", "").strip() or "5s"

# Kinesis mock log level override when inconsistent with LS_LOG (e.g., when LS_LOG=debug)
KINESIS_MOCK_LOG_LEVEL = os.environ.get("KINESIS_MOCK_LOG_LEVEL", "").strip()

# DEPRECATED: 1 (default) only applies to old lambda provider
# Whether to handle Kinesis Lambda event sources as synchronous invocations.
SYNCHRONOUS_KINESIS_EVENTS = is_env_not_false("SYNCHRONOUS_KINESIS_EVENTS")  # DEPRECATED

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

# the port on which to expose dynamodblocal
DYNAMODB_LOCAL_PORT = int(os.environ.get("DYNAMODB_LOCAL_PORT") or 0)

# Used to toggle PurgeInProgress exceptions when calling purge within 60 seconds
SQS_DELAY_PURGE_RETRY = is_env_true("SQS_DELAY_PURGE_RETRY")

# Used to toggle QueueDeletedRecently errors when re-creating a queue within 60 seconds of deleting it
SQS_DELAY_RECENTLY_DELETED = is_env_true("SQS_DELAY_RECENTLY_DELETED")

# expose SQS on a specific port externally
SQS_PORT_EXTERNAL = int(os.environ.get("SQS_PORT_EXTERNAL") or 0)

# Strategy used when creating SQS queue urls. can be "off", "standard" (default), "domain", or "path"
SQS_ENDPOINT_STRATEGY = os.environ.get("SQS_ENDPOINT_STRATEGY", "") or "standard"

# Disable the check for MaxNumberOfMessage in SQS ReceiveMessage
SQS_DISABLE_MAX_NUMBER_OF_MESSAGE_LIMIT = is_env_true("SQS_DISABLE_MAX_NUMBER_OF_MESSAGE_LIMIT")

# Disable cloudwatch metrics for SQS
SQS_DISABLE_CLOUDWATCH_METRICS = is_env_true("SQS_DISABLE_CLOUDWATCH_METRICS")

# Interval for reporting "approximate" metrics to cloudwatch, default is 60 seconds
SQS_CLOUDWATCH_METRICS_REPORT_INTERVAL = int(
    os.environ.get("SQS_CLOUDWATCH_METRICS_REPORT_INTERVAL") or 60
)

# DEPRECATED: only applies to old lambda provider
# Endpoint host under which LocalStack APIs are accessible from Lambda Docker containers.
HOSTNAME_FROM_LAMBDA = os.environ.get("HOSTNAME_FROM_LAMBDA", "").strip()

# DEPRECATED: true (default) only applies to old lambda provider
# Determines whether Lambda code is copied or mounted into containers.
LAMBDA_REMOTE_DOCKER = is_env_true("LAMBDA_REMOTE_DOCKER")
# make sure we default to LAMBDA_REMOTE_DOCKER=true if running in Docker
if is_in_docker and not os.environ.get("LAMBDA_REMOTE_DOCKER", "").strip():
    LAMBDA_REMOTE_DOCKER = True

# PUBLIC: hot-reload (default v2), __local__ (default v1)
# Magic S3 bucket name for Hot Reloading. The S3Key points to the source code on the local file system.
BUCKET_MARKER_LOCAL = (
    os.environ.get("BUCKET_MARKER_LOCAL", "").strip() or DEFAULT_BUCKET_MARKER_LOCAL
)

# PUBLIC: bridge (Docker default)
# Docker network driver for the Lambda and ECS containers. https://docs.docker.com/network/
LAMBDA_DOCKER_NETWORK = os.environ.get("LAMBDA_DOCKER_NETWORK", "").strip()

# PUBLIC v1: Currently only supported by the old lambda provider
# Custom DNS server for the container running your lambda function.
LAMBDA_DOCKER_DNS = os.environ.get("LAMBDA_DOCKER_DNS", "").strip()

# PUBLIC: -e KEY=VALUE -v host:container
# Additional flags passed to Docker run|create commands.
LAMBDA_DOCKER_FLAGS = os.environ.get("LAMBDA_DOCKER_FLAGS", "").strip()

# PUBLIC: 0 (default)
# Enable this flag to run cross-platform compatible lambda functions natively (i.e., Docker selects architecture) and
# ignore the AWS architectures (i.e., x86_64, arm64) configured for the lambda function.
LAMBDA_IGNORE_ARCHITECTURE = is_env_true("LAMBDA_IGNORE_ARCHITECTURE")

# TODO: test and add to docs
# EXPERIMENTAL: 0 (default)
# prebuild images before execution? Increased cold start time on the tradeoff of increased time until lambda is ACTIVE
LAMBDA_PREBUILD_IMAGES = is_env_true("LAMBDA_PREBUILD_IMAGES")

# PUBLIC: docker (default), kubernetes (pro)
# Where Lambdas will be executed.
LAMBDA_RUNTIME_EXECUTOR = os.environ.get("LAMBDA_RUNTIME_EXECUTOR", "").strip()

# PUBLIC: 10 (default)
# How many seconds Lambda will wait for the runtime environment to start up.
LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT = int(os.environ.get("LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT") or 10)

# DEPRECATED: lambci/lambda (default) only applies to old lambda provider
# An alternative docker registry from where to pull lambda execution containers.
# Replaced by LAMBDA_RUNTIME_IMAGE_MAPPING in new provider.
LAMBDA_CONTAINER_REGISTRY = (
    os.environ.get("LAMBDA_CONTAINER_REGISTRY", "").strip() or DEFAULT_LAMBDA_CONTAINER_REGISTRY
)

# PUBLIC: base images for Lambda (default) https://docs.aws.amazon.com/lambda/latest/dg/runtimes-images.html
# localstack/services/lambda_/invocation/lambda_models.py:IMAGE_MAPPING
# Customize the Docker image of Lambda runtimes, either by:
# a) pattern with <runtime> placeholder, e.g. custom-repo/lambda-<runtime>:2022
# b) json dict mapping the <runtime> to an image, e.g. {"python3.9": "custom-repo/lambda-py:thon3.9"}
LAMBDA_RUNTIME_IMAGE_MAPPING = os.environ.get("LAMBDA_RUNTIME_IMAGE_MAPPING", "").strip()

# PUBLIC: 1 (default)
# Whether to remove any Lambda Docker containers.
LAMBDA_REMOVE_CONTAINERS = (
    os.environ.get("LAMBDA_REMOVE_CONTAINERS", "").lower().strip() not in FALSE_STRINGS
)

# PUBLIC: 600000 (default 10min)
# Time in milliseconds until lambda shuts down the execution environment after the last invocation has been processed.
# Set to 0 to immediately shut down the execution environment after an invocation.
LAMBDA_KEEPALIVE_MS = int(os.environ.get("LAMBDA_KEEPALIVE_MS", 600_000))

# PUBLIC: 1000 (default)
# The maximum number of events that functions can process simultaneously in the current Region.
# See AWS service quotas: https://docs.aws.amazon.com/general/latest/gr/lambda-service.html
# Concurrency limits. Like on AWS these apply per account and region.
LAMBDA_LIMITS_CONCURRENT_EXECUTIONS = int(
    os.environ.get("LAMBDA_LIMITS_CONCURRENT_EXECUTIONS", 1_000)
)
# SEMI-PUBLIC: not actively communicated
# per account/region: there must be at least <LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY> unreserved concurrency.
LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY = int(
    os.environ.get("LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY", 100)
)
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_TOTAL_CODE_SIZE = int(os.environ.get("LAMBDA_LIMITS_TOTAL_CODE_SIZE", 80_530_636_800))
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_CODE_SIZE_ZIPPED = int(os.environ.get("LAMBDA_LIMITS_CODE_SIZE_ZIPPED", 52_428_800))
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_CODE_SIZE_UNZIPPED = int(
    os.environ.get("LAMBDA_LIMITS_CODE_SIZE_UNZIPPED", 262_144_000)
)
# PUBLIC: documented upon customer request
LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE = int(
    os.environ.get("LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE", 69_905_067)
)
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES = int(
    os.environ.get("LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES", 4 * 1024)
)

# DEV: 0 (default) only applies to new lambda provider. For LS developers only.
# Whether to explicitly expose a free TCP port in lambda containers when invoking functions in host mode for
# systems that cannot reach the container via its IPv4. For example, macOS cannot reach Docker containers:
# https://docs.docker.com/desktop/networking/#i-cannot-ping-my-containers
LAMBDA_DEV_PORT_EXPOSE = is_env_true("LAMBDA_DEV_PORT_EXPOSE")

# DEV: only applies to new lambda provider. All LAMBDA_INIT_* configuration are for LS developers only.
# There are NO stability guarantees, and they may break at any time.

# DEV: Release version of https://github.com/localstack/lambda-runtime-init overriding the current default
LAMBDA_INIT_RELEASE_VERSION = os.environ.get("LAMBDA_INIT_RELEASE_VERSION")
# DEV: 0 (default) Enable for mounting of RIE init binary and delve debugger
LAMBDA_INIT_DEBUG = is_env_true("LAMBDA_INIT_DEBUG")
# DEV: path to RIE init binary (e.g., var/rapid/init)
LAMBDA_INIT_BIN_PATH = os.environ.get("LAMBDA_INIT_BIN_PATH")
# DEV: path to entrypoint script (e.g., var/rapid/entrypoint.sh)
LAMBDA_INIT_BOOTSTRAP_PATH = os.environ.get("LAMBDA_INIT_BOOTSTRAP_PATH")
# DEV: path to delve debugger (e.g., var/rapid/dlv)
LAMBDA_INIT_DELVE_PATH = os.environ.get("LAMBDA_INIT_DELVE_PATH")
# DEV: Go Delve debug port
LAMBDA_INIT_DELVE_PORT = int(os.environ.get("LAMBDA_INIT_DELVE_PORT") or 40000)
# DEV: Time to wait after every invoke as a workaround to fix a race condition in persistence tests
LAMBDA_INIT_POST_INVOKE_WAIT_MS = os.environ.get("LAMBDA_INIT_POST_INVOKE_WAIT_MS")
# DEV: sbx_user1051 (default when not provided) Alternative system user or empty string to skip dropping privileges.
LAMBDA_INIT_USER = os.environ.get("LAMBDA_INIT_USER")

# Adding Stepfunctions default port
LOCAL_PORT_STEPFUNCTIONS = int(os.environ.get("LOCAL_PORT_STEPFUNCTIONS") or 8083)
# Stepfunctions lambda endpoint override
STEPFUNCTIONS_LAMBDA_ENDPOINT = os.environ.get("STEPFUNCTIONS_LAMBDA_ENDPOINT", "").strip()

# path prefix for windows volume mounting
WINDOWS_DOCKER_MOUNT_PREFIX = os.environ.get("WINDOWS_DOCKER_MOUNT_PREFIX", "/host_mnt")

# whether to skip S3 presign URL signature validation (TODO: currently enabled, until all issues are resolved)
S3_SKIP_SIGNATURE_VALIDATION = is_env_not_false("S3_SKIP_SIGNATURE_VALIDATION")
# whether to skip S3 validation of provided KMS key
S3_SKIP_KMS_KEY_VALIDATION = is_env_not_false("S3_SKIP_KMS_KEY_VALIDATION")

# DEPRECATED: docker (default), local (fallback without Docker), docker-reuse. only applies to old lambda provider
# Method to use for executing Lambda functions.
LAMBDA_EXECUTOR = os.environ.get("LAMBDA_EXECUTOR", "").strip()

# DEPRECATED: only applies to old lambda provider
# Fallback URL to use when a non-existing Lambda is invoked. If this matches
# `dynamodb://<table_name>`, then the invocation is recorded in the corresponding
# DynamoDB table. If this matches `http(s)://...`, then the Lambda invocation is
# forwarded as a POST request to that URL.
LAMBDA_FALLBACK_URL = os.environ.get("LAMBDA_FALLBACK_URL", "").strip()
# DEPRECATED: only applies to old lambda provider
# Forward URL used to forward any Lambda invocations to an external
# endpoint (can use useful for advanced test setups)
LAMBDA_FORWARD_URL = os.environ.get("LAMBDA_FORWARD_URL", "").strip()
# DEPRECATED: ignored in new lambda provider because creation happens asynchronously
# Time in seconds to wait at max while extracting Lambda code.
# By default, it is 25 seconds for limiting the execution time
# to avoid client/network timeout issues
LAMBDA_CODE_EXTRACT_TIME = int(os.environ.get("LAMBDA_CODE_EXTRACT_TIME") or 25)

# DEPRECATED: 1 (default) only applies to old lambda provider
# whether lambdas should use stay open mode if executed in "docker-reuse" executor
LAMBDA_STAY_OPEN_MODE = is_in_docker and is_env_not_false("LAMBDA_STAY_OPEN_MODE")

# PUBLIC: 2000 (default)
# Allows increasing the default char limit for truncation of lambda log lines when printed in the console.
# This does not affect the logs processing in CloudWatch.
LAMBDA_TRUNCATE_STDOUT = int(os.getenv("LAMBDA_TRUNCATE_STDOUT") or 2000)

# INTERNAL: 60 (default matching AWS) only applies to new lambda provider
# Base delay in seconds for async retries. Further retries use: NUM_ATTEMPTS * LAMBDA_RETRY_BASE_DELAY_SECONDS
# 300 (5min) is the maximum because NUM_ATTEMPTS can be at most 3 and SQS has a message timer limit of 15 min.
# For example:
# 1x LAMBDA_RETRY_BASE_DELAY_SECONDS: delay between initial invocation and first retry
# 2x LAMBDA_RETRY_BASE_DELAY_SECONDS: delay between the first retry and the second retry
# 3x LAMBDA_RETRY_BASE_DELAY_SECONDS: delay between the second retry and the third retry
LAMBDA_RETRY_BASE_DELAY_SECONDS = int(os.getenv("LAMBDA_RETRY_BASE_DELAY") or 60)

# PUBLIC: 0 (default)
# Set to 1 to create lambda functions synchronously (not recommended).
# Whether Lambda.CreateFunction will block until the function is in a terminal state (Active or Failed).
# This technically breaks behavior parity but is provided as a simplification over the default AWS behavior and
# to match the behavior of the old lambda provider.
LAMBDA_SYNCHRONOUS_CREATE = is_env_true("LAMBDA_SYNCHRONOUS_CREATE")

# A comma-delimited string of stream names and its corresponding shard count to
# initialize during startup (DEPRECATED).
# For example: "my-first-stream:1,my-other-stream:2,my-last-stream:1"
KINESIS_INITIALIZE_STREAMS = os.environ.get("KINESIS_INITIALIZE_STREAMS", "").strip()

# KMS provider - can be either "local-kms" or "moto"
KMS_PROVIDER = (os.environ.get("KMS_PROVIDER") or "").strip() or "moto"

# URL to a custom OpenSearch/Elasticsearch backend cluster. If this is set to a valid URL, then localstack will not
# create OpenSearch/Elasticsearch cluster instances, but instead forward all domains to the given backend.
# `ES_CUSTOM_BACKEND` is DEPRECATED!
OPENSEARCH_CUSTOM_BACKEND = (
    os.environ.get("OPENSEARCH_CUSTOM_BACKEND", "").strip()
    or os.environ.get("ES_CUSTOM_BACKEND", "").strip()
)

# Strategy used when creating OpenSearch/Elasticsearch domain endpoints routed through the edge proxy
# valid values: domain | path | port (off)
# `ES_ENDPOINT_STRATEGY` is DEPRECATED!
OPENSEARCH_ENDPOINT_STRATEGY = (
    os.environ.get("OPENSEARCH_ENDPOINT_STRATEGY", "").strip()
    or os.environ.get("ES_ENDPOINT_STRATEGY", "").strip()
    or "domain"
)
if OPENSEARCH_ENDPOINT_STRATEGY == "off":
    OPENSEARCH_ENDPOINT_STRATEGY = "port"

# Whether to start one cluster per domain (default), or multiplex opensearch domains to a single clusters
# `ES_MULTI_CLUSTER` is DEPRECATED!
OPENSEARCH_MULTI_CLUSTER = is_env_not_false("OPENSEARCH_MULTI_CLUSTER") or is_env_true(
    "ES_MULTI_CLUSTER"
)

# Whether to really publish to GCM while using SNS Platform Application (needs credentials)
LEGACY_SNS_GCM_PUBLISHING = is_env_true("LEGACY_SNS_GCM_PUBLISHING")

# TODO remove fallback to LAMBDA_DOCKER_NETWORK with next minor version
MAIN_DOCKER_NETWORK = os.environ.get("MAIN_DOCKER_NETWORK", "") or LAMBDA_DOCKER_NETWORK

# Whether to return and parse access key ids starting with an "A", like on AWS
PARITY_AWS_ACCESS_KEY_ID = is_env_true("PARITY_AWS_ACCESS_KEY_ID")

# Show exceptions for CloudFormation deploy errors
CFN_VERBOSE_ERRORS = is_env_true("CFN_VERBOSE_ERRORS")

# How localstack will react to encountering unsupported resource types.
# By default unsupported resource types will be ignored.
# EXPERIMENTAL
CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES = is_env_not_false("CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES")

# Selectively enable/disable new resource providers
# e.g. CFN_RESOURCE_PROVIDER_OVERRIDES='{"AWS::Lambda::Version": "GenericBaseModel","AWS::Lambda::Function": "ResourceProvider"}'
CFN_RESOURCE_PROVIDER_OVERRIDES = os.environ.get("CFN_RESOURCE_PROVIDER_OVERRIDES", "{}")

# bind address of local DNS server
DNS_ADDRESS = os.environ.get("DNS_ADDRESS") or "0.0.0.0"
# port of the local DNS server
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))

# Comma-separated list of regex patterns for DNS names to resolve locally.
# Any DNS name not matched against any of the patterns on this whitelist
# will resolve to the real DNS entry, rather than the local one.
DNS_LOCAL_NAME_PATTERNS = (os.environ.get("DNS_LOCAL_NAME_PATTERNS") or "").strip()

# IP address that AWS endpoints should resolve to in our local DNS server. By default,
# hostnames resolve to 127.0.0.1, which allows to use the LocalStack APIs transparently
# from the host machine. If your code is running in Docker, this should be configured
# to resolve to the Docker bridge network address, e.g., DNS_RESOLVE_IP=172.17.0.1
DNS_RESOLVE_IP = os.environ.get("DNS_RESOLVE_IP") or LOCALHOST_IP

# fallback DNS server to send upstream requests to
DNS_SERVER = os.environ.get("DNS_SERVER")
DNS_VERIFICATION_DOMAIN = os.environ.get("DNS_VERIFICATION_DOMAIN") or "localstack.cloud"


def use_custom_dns():
    return str(DNS_ADDRESS) not in FALSE_STRINGS


BOTO_WAITER_DELAY = int(os.environ.get("BOTO_WAITER_DELAY") or "1")
BOTO_WAITER_MAX_ATTEMPTS = int(os.environ.get("BOTO_WAITER_MAX_ATTEMPTS") or "120")
DISABLE_CUSTOM_BOTO_WAITER_CONFIG = is_env_true("DISABLE_CUSTOM_BOTO_WAITER_CONFIG")

# defaults to false
# if `DISABLE_BOTO_RETRIES=1` is set, all our created boto clients will have retries disabled
DISABLE_BOTO_RETRIES = is_env_true("DISABLE_BOTO_RETRIES")

# HINT: Please add deprecated environment variables to deprecations.py

# List of environment variable names used for configuration that are passed from the host into the LocalStack container.
# Make sure to keep this in sync with the above!
# Do *not* include any internal developer configurations that apply to host-mode only in this list.
# Note: do *not* include DATA_DIR in this list, as it is treated separately
CONFIG_ENV_VARS = [
    "ALLOW_NONSTANDARD_REGIONS",
    "BOTO_WAITER_DELAY",
    "BOTO_WAITER_MAX_ATTEMPTS",
    "BUCKET_MARKER_LOCAL",
    "CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES",
    "CFN_VERBOSE_ERRORS",
    "CFN_RESOURCE_PROVIDER_OVERRIDES",
    "CI",
    "CUSTOM_SSL_CERT_PATH",
    "DEBUG",
    "DEBUG_HANDLER_CHAIN",
    "DEFAULT_REGION",
    "DEVELOP",
    "DEVELOP_PORT",
    "DISABLE_BOTO_RETRIES",
    "DISABLE_CORS_CHECKS",
    "DISABLE_CORS_HEADERS",
    "DISABLE_CUSTOM_BOTO_WAITER_CONFIG",
    "DISABLE_CUSTOM_CORS_APIGATEWAY",
    "DISABLE_CUSTOM_CORS_S3",
    "DISABLE_EVENTS",
    "DNS_ADDRESS",
    "DNS_PORT",
    "DNS_LOCAL_NAME_PATTERNS",
    "DNS_RESOLVE_IP",
    "DNS_SERVER",
    "DNS_VERIFICATION_DOMAIN",
    "DOCKER_BRIDGE_IP",
    "DOCKER_SDK_DEFAULT_TIMEOUT_SECONDS",
    "DYNAMODB_ERROR_PROBABILITY",
    "DYNAMODB_HEAP_SIZE",
    "DYNAMODB_IN_MEMORY",
    "DYNAMODB_LOCAL_PORT",
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
    "GATEWAY_LISTEN",
    "HOSTNAME",
    "HOSTNAME_EXTERNAL",
    "HOSTNAME_FROM_LAMBDA",
    "KINESIS_ERROR_PROBABILITY",
    "KINESIS_INITIALIZE_STREAMS",
    "KINESIS_MOCK_PERSIST_INTERVAL",
    "KINESIS_MOCK_LOG_LEVEL",
    "KINESIS_ON_DEMAND_STREAM_COUNT_LIMIT",
    "LAMBDA_CODE_EXTRACT_TIME",
    "LAMBDA_CONTAINER_REGISTRY",
    "LAMBDA_DOCKER_DNS",
    "LAMBDA_DOCKER_FLAGS",
    "LAMBDA_DOCKER_NETWORK",
    "LAMBDA_EXECUTOR",
    "LAMBDA_FALLBACK_URL",
    "LAMBDA_FORWARD_URL",
    "LAMBDA_INIT_DEBUG",
    "LAMBDA_INIT_BIN_PATH",
    "LAMBDA_INIT_BOOTSTRAP_PATH",
    "LAMBDA_INIT_DELVE_PATH",
    "LAMBDA_INIT_DELVE_PORT",
    "LAMBDA_INIT_POST_INVOKE_WAIT_MS",
    "LAMBDA_INIT_USER",
    "LAMBDA_INIT_RELEASE_VERSION",
    "LAMBDA_KEEPALIVE_MS",
    "LAMBDA_RUNTIME_IMAGE_MAPPING",
    "LAMBDA_JAVA_OPTS",
    "LAMBDA_REMOTE_DOCKER",
    "LAMBDA_REMOVE_CONTAINERS",
    "LAMBDA_RUNTIME_EXECUTOR",
    "LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT",
    "LAMBDA_STAY_OPEN_MODE",
    "LAMBDA_TRUNCATE_STDOUT",
    "LAMBDA_RETRY_BASE_DELAY_SECONDS",
    "LAMBDA_SYNCHRONOUS_CREATE",
    "LAMBDA_LIMITS_CONCURRENT_EXECUTIONS",
    "LAMBDA_LIMITS_MINIMUM_UNRESERVED_CONCURRENCY",
    "LAMBDA_LIMITS_TOTAL_CODE_SIZE",
    "LAMBDA_LIMITS_CODE_SIZE_ZIPPED",
    "LAMBDA_LIMITS_CODE_SIZE_UNZIPPED",
    "LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE",
    "LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES",
    "LEGACY_DIRECTORIES",
    "LEGACY_DOCKER_CLIENT",
    "LEGACY_EDGE_PROXY",
    "LEGACY_SNS_GCM_PUBLISHING",
    "LOCALSTACK_API_KEY",
    "LOCALSTACK_AUTH_TOKEN",
    "LOCALSTACK_HOST",
    "LOCALSTACK_HOSTNAME",
    "LOG_LICENSE_ISSUES",
    "LS_LOG",
    "MAIN_CONTAINER_NAME",
    "MAIN_DOCKER_NETWORK",
    "OPENSEARCH_ENDPOINT_STRATEGY",
    "OUTBOUND_HTTP_PROXY",
    "OUTBOUND_HTTPS_PROXY",
    "PARITY_AWS_ACCESS_KEY_ID",
    "PERSISTENCE",
    "PORTS_CHECK_DOCKER_IMAGE",
    "REQUESTS_CA_BUNDLE",
    "S3_SKIP_SIGNATURE_VALIDATION",
    "S3_SKIP_KMS_KEY_VALIDATION",
    "SERVICES",
    "SKIP_INFRA_DOWNLOADS",
    "SKIP_SSL_CERT_DOWNLOAD",
    "SNAPSHOT_LOAD_STRATEGY",
    "SNAPSHOT_SAVE_STRATEGY",
    "SNAPSHOT_FLUSH_INTERVAL",
    "SQS_DELAY_PURGE_RETRY",
    "SQS_DELAY_RECENTLY_DELETED",
    "SQS_ENDPOINT_STRATEGY",
    "SQS_PORT_EXTERNAL",
    "SQS_DISABLE_CLOUDWATCH_METRICS",
    "SQS_CLOUDWATCH_METRICS_REPORT_INTERVAL",
    "STEPFUNCTIONS_LAMBDA_ENDPOINT",
    "SYNCHRONOUS_KINESIS_EVENTS",
    "SYNCHRONOUS_SNS_EVENTS",
    "TEST_AWS_ACCOUNT_ID",
    "TF_COMPAT_MODE",
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


def populate_config_env_var_names():
    global CONFIG_ENV_VARS

    CONFIG_ENV_VARS += [
        key
        for key in [key.upper() for key in os.environ]
        if (key.startswith("LOCALSTACK_") or key.startswith("PROVIDER_OVERRIDE_"))
        # explicitly exclude LOCALSTACK_CLI (it's prefixed with "LOCALSTACK_",
        # but is only used in the CLI (should not be forwarded to the container)
        and key != "LOCALSTACK_CLI"
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
    return get_edge_port_http()


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


# FIXME: we don't separate http and non-http ports any more,
#        so this function should be removed
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
            if key.startswith(self.override_prefix) and value:
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


def init_directories() -> Directories:
    if is_in_docker:
        return Directories.for_container()
    else:
        if is_env_true("LOCALSTACK_CLI"):
            return Directories.for_cli()

        return Directories.for_host()


# initialize directories
dirs: Directories
dirs = init_directories()
