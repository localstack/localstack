import logging
import os
import platform
import socket
import subprocess
import tempfile
import time
import warnings
from typing import Any, Dict, List, Mapping, Optional, Tuple, TypeVar, Union

from localstack import constants
from localstack.constants import (
    DEFAULT_BUCKET_MARKER_LOCAL,
    DEFAULT_DEVELOP_PORT,
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
        tmp:         container only; ephemeral data that has to persist across localstack runs but not reboots
        mounted_tmp: shared; same as above, but shared for persistence across different containers, tests, ...
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
    mounted_tmp: str
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
        mounted_tmp: str,
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
        self.mounted_tmp = mounted_tmp
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
            tmp=os.path.join(tempfile.gettempdir(), "localstack"),
            mounted_tmp=f"{DEFAULT_VOLUME_DIR}/tmp",
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
        lives in /var/lib/localstack or {tempfile.gettempdir()}/localstack.

        :returns: Directories object
        """
        defaults = Directories.defaults()

        return Directories(
            static_libs=defaults.static_libs,
            var_libs=defaults.var_libs,
            cache=defaults.cache,
            tmp=defaults.tmp,
            mounted_tmp=defaults.mounted_tmp,
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
            mounted_tmp=os.path.join(root, defaults.mounted_tmp.lstrip("/")),
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
            mounted_tmp=tmp_dir,
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
            self.mounted_tmp,
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


def load_environment(profiles: str = None, env=os.environ) -> List[str]:
    """Loads the environment variables from ~/.localstack/{profile}.env, for each profile listed in the profiles.
    :param env: environment to load profile to. Defaults to `os.environ`
    :param profiles: a comma separated list of profiles to load (defaults to "default")
    :returns str: the list of the actually loaded profiles (might be the fallback)
    """
    if not profiles:
        profiles = "default"

    profiles = profiles.split(",")
    environment = {}
    import dotenv

    for profile in profiles:
        profile = profile.strip()
        path = os.path.join(CONFIG_DIR, f"{profile}.env")
        if not os.path.exists(path):
            continue
        environment.update(dotenv.dotenv_values(path))

    for k, v in environment.items():
        # we do not want to override the environment
        if k not in env and v is not None:
            env[k] = v

    return profiles


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
    LOADED_PROFILES = load_environment(CONFIG_PROFILE)
except ImportError:
    # dotenv may not be available in lambdas or other environments where config is loaded
    LOADED_PROFILES = None

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

# whether to enable verbose debug logging
LS_LOG = eval_log_type("LS_LOG")
DEBUG = is_env_true("DEBUG") or LS_LOG in TRACE_LOG_LEVELS

# whether to enable debugpy
DEVELOP = is_env_true("DEVELOP")

# PORT FOR DEBUGGER
DEVELOP_PORT = int(os.environ.get("DEVELOP_PORT", "").strip() or DEFAULT_DEVELOP_PORT)

# whether to make debugpy wait for a debbuger client
WAIT_FOR_DEBUGGER = is_env_true("WAIT_FOR_DEBUGGER")

# whether to assume http or https for `get_protocol`
USE_SSL = is_env_true("USE_SSL")

# whether the S3 legacy V2/ASF provider is enabled
LEGACY_V2_S3_PROVIDER = os.environ.get("PROVIDER_OVERRIDE_S3", "") in ("v2", "legacy_v2", "asf")

# Whether to report internal failures as 500 or 501 errors.
FAIL_FAST = is_env_true("FAIL_FAST")

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

    def host_and_port(self):
        return f"{self.host}:{self.port}" if self.port is not None else self.host

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
        return self.host_and_port()

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


def populate_edge_configuration(
    environment: Mapping[str, str]
) -> Tuple[HostAndPort, UniqueHostAndPortList]:
    """Populate the LocalStack edge configuration from environment variables."""
    localstack_host_raw = environment.get("LOCALSTACK_HOST")
    gateway_listen_raw = environment.get("GATEWAY_LISTEN")

    # parse gateway listen from multiple components
    if gateway_listen_raw is not None:
        gateway_listen = []
        for address in gateway_listen_raw.split(","):
            gateway_listen.append(
                HostAndPort.parse(
                    address.strip(),
                    default_host=default_ip,
                    default_port=constants.DEFAULT_PORT_EDGE,
                )
            )
    else:
        # use default if gateway listen is not defined
        gateway_listen = [HostAndPort(host=default_ip, port=constants.DEFAULT_PORT_EDGE)]

    # the actual value of the LOCALSTACK_HOST port now depends on what gateway listen actually listens to.
    if localstack_host_raw is None:
        localstack_host = HostAndPort(
            host=constants.LOCALHOST_HOSTNAME, port=gateway_listen[0].port
        )
    else:
        localstack_host = HostAndPort.parse(
            localstack_host_raw,
            default_host=constants.LOCALHOST_HOSTNAME,
            default_port=gateway_listen[0].port,
        )

    assert gateway_listen is not None
    assert localstack_host is not None

    return (
        localstack_host,
        UniqueHostAndPortList(gateway_listen),
    )


# How to access LocalStack
(
    # -- Cosmetic
    LOCALSTACK_HOST,
    # -- Edge configuration
    # Main configuration of the listen address of the hypercorn proxy. Of the form
    # <ip_address>:<port>(,<ip_address>:port>)*
    GATEWAY_LISTEN,
) = populate_edge_configuration(os.environ)

GATEWAY_WORKER_COUNT = int(os.environ.get("GATEWAY_WORKER_COUNT") or 1000)

# the gateway server that should be used (supported: hypercorn, twisted dev: werkzeug)
GATEWAY_SERVER = os.environ.get("GATEWAY_SERVER", "").strip() or "hypercorn"

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

# whether to selectively load services in SERVICES
STRICT_SERVICE_LOADING = is_env_not_false("STRICT_SERVICE_LOADING")

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
MAIN_CONTAINER_NAME = os.environ.get("MAIN_CONTAINER_NAME", "").strip() or "localstack-main"

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

# Fallback partition to use if not possible to determine from ARN region.
# Applicable only when ARN partition rewriting is enabled.
ARN_PARTITION_FALLBACK = os.environ.get("ARN_PARTITION_FALLBACK", "") or "aws"

# whether to skip waiting for the infrastructure to shut down, or exit immediately
FORCE_SHUTDOWN = is_env_not_false("FORCE_SHUTDOWN")

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
KINESIS_PERSISTENCE = is_env_not_false("KINESIS_PERSISTENCE")

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

# Enables the automatic removal of stale KV pais based on TTL
DYNAMODB_REMOVE_EXPIRED_ITEMS = is_env_true("DYNAMODB_REMOVE_EXPIRED_ITEMS")

# Used to toggle PurgeInProgress exceptions when calling purge within 60 seconds
SQS_DELAY_PURGE_RETRY = is_env_true("SQS_DELAY_PURGE_RETRY")

# Used to toggle QueueDeletedRecently errors when re-creating a queue within 60 seconds of deleting it
SQS_DELAY_RECENTLY_DELETED = is_env_true("SQS_DELAY_RECENTLY_DELETED")

# Used to toggle MessageRetentionPeriod functionality in SQS queues
SQS_ENABLE_MESSAGE_RETENTION_PERIOD = is_env_true("SQS_ENABLE_MESSAGE_RETENTION_PERIOD")

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

# PUBLIC: Endpoint host under which LocalStack APIs are accessible from Lambda Docker containers.
HOSTNAME_FROM_LAMBDA = os.environ.get("HOSTNAME_FROM_LAMBDA", "").strip()

# PUBLIC: hot-reload (default v2), __local__ (default v1)
# Magic S3 bucket name for Hot Reloading. The S3Key points to the source code on the local file system.
BUCKET_MARKER_LOCAL = (
    os.environ.get("BUCKET_MARKER_LOCAL", "").strip() or DEFAULT_BUCKET_MARKER_LOCAL
)

# PUBLIC: Opt-out to inject the environment variable AWS_ENDPOINT_URL for automatic configuration of AWS SDKs:
# https://docs.aws.amazon.com/sdkref/latest/guide/feature-ss-endpoints.html
LAMBDA_DISABLE_AWS_ENDPOINT_URL = is_env_true("LAMBDA_DISABLE_AWS_ENDPOINT_URL")

# PUBLIC: bridge (Docker default)
# Docker network driver for the Lambda and ECS containers. https://docs.docker.com/network/
LAMBDA_DOCKER_NETWORK = os.environ.get("LAMBDA_DOCKER_NETWORK", "").strip()

# PUBLIC v1: LocalStack DNS (default)
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

# PUBLIC: 20 (default)
# How many seconds Lambda will wait for the runtime environment to start up.
LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT = int(os.environ.get("LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT") or 20)

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
# PUBLIC: documented after AWS changed validation around 2023-11
LAMBDA_LIMITS_CODE_SIZE_ZIPPED = int(os.environ.get("LAMBDA_LIMITS_CODE_SIZE_ZIPPED", 52_428_800))
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_CODE_SIZE_UNZIPPED = int(
    os.environ.get("LAMBDA_LIMITS_CODE_SIZE_UNZIPPED", 262_144_000)
)
# PUBLIC: documented upon customer request
LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE = int(
    os.environ.get("LAMBDA_LIMITS_CREATE_FUNCTION_REQUEST_SIZE", 70_167_211)
)
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES = int(
    os.environ.get("LAMBDA_LIMITS_MAX_FUNCTION_ENVVAR_SIZE_BYTES", 4 * 1024)
)
# SEMI-PUBLIC: not actively communicated
LAMBDA_LIMITS_MAX_FUNCTION_PAYLOAD_SIZE_BYTES = int(
    os.environ.get(
        "LAMBDA_LIMITS_MAX_FUNCTION_PAYLOAD_SIZE_BYTES", 6 * 1024 * 1024 + 100
    )  # the 100 comes from the init defaults
)

LAMBDA_EVENTS_INTERNAL_SQS = is_env_not_false("LAMBDA_EVENTS_INTERNAL_SQS")

LAMBDA_SQS_EVENT_SOURCE_MAPPING_INTERVAL_SEC = float(
    os.environ.get("LAMBDA_SQS_EVENT_SOURCE_MAPPING_INTERVAL_SEC") or 1.0
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

# URL to a custom OpenSearch/Elasticsearch backend cluster. If this is set to a valid URL, then localstack will not
# create OpenSearch/Elasticsearch cluster instances, but instead forward all domains to the given backend.
OPENSEARCH_CUSTOM_BACKEND = os.environ.get("OPENSEARCH_CUSTOM_BACKEND", "").strip()

# Strategy used when creating OpenSearch/Elasticsearch domain endpoints routed through the edge proxy
# valid values: domain | path | port (off)
OPENSEARCH_ENDPOINT_STRATEGY = (
    os.environ.get("OPENSEARCH_ENDPOINT_STRATEGY", "").strip() or "domain"
)
if OPENSEARCH_ENDPOINT_STRATEGY == "off":
    OPENSEARCH_ENDPOINT_STRATEGY = "port"

# Whether to start one cluster per domain (default), or multiplex opensearch domains to a single clusters
OPENSEARCH_MULTI_CLUSTER = is_env_not_false("OPENSEARCH_MULTI_CLUSTER")

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

# bind address of local DNS server
DNS_ADDRESS = os.environ.get("DNS_ADDRESS") or "0.0.0.0"
# port of the local DNS server
DNS_PORT = int(os.environ.get("DNS_PORT", "53"))

# Comma-separated list of regex patterns for DNS names to resolve locally.
# Any DNS name not matched against any of the patterns on this whitelist
# will resolve to the real DNS entry, rather than the local one.
DNS_NAME_PATTERNS_TO_RESOLVE_UPSTREAM = (
    os.environ.get("DNS_NAME_PATTERNS_TO_RESOLVE_UPSTREAM") or ""
).strip()
DNS_LOCAL_NAME_PATTERNS = (os.environ.get("DNS_LOCAL_NAME_PATTERNS") or "").strip()  # deprecated

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


# s3 virtual host name
S3_VIRTUAL_HOSTNAME = "s3.%s" % LOCALSTACK_HOST.host
S3_STATIC_WEBSITE_HOSTNAME = "s3-website.%s" % LOCALSTACK_HOST.host

BOTO_WAITER_DELAY = int(os.environ.get("BOTO_WAITER_DELAY") or "1")
BOTO_WAITER_MAX_ATTEMPTS = int(os.environ.get("BOTO_WAITER_MAX_ATTEMPTS") or "120")
DISABLE_CUSTOM_BOTO_WAITER_CONFIG = is_env_true("DISABLE_CUSTOM_BOTO_WAITER_CONFIG")

# defaults to false
# if `DISABLE_BOTO_RETRIES=1` is set, all our created boto clients will have retries disabled
DISABLE_BOTO_RETRIES = is_env_true("DISABLE_BOTO_RETRIES")

# List of environment variable names used for configuration that are passed from the host into the LocalStack container.
# => Synchronize this list with the above and the configuration docs:
# https://docs.localstack.cloud/references/configuration/
# => Sort this list alphabetically
# => Add deprecated environment variables to deprecations.py and add a comment in this list
# => Move removed legacy variables to the section grouped by release (still relevant for deprecation warnings)
# => Do *not* include any internal developer configurations that apply to host-mode only in this list.
CONFIG_ENV_VARS = [
    "ALLOW_NONSTANDARD_REGIONS",
    "BOTO_WAITER_DELAY",
    "BOTO_WAITER_MAX_ATTEMPTS",
    "BUCKET_MARKER_LOCAL",
    "CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES",
    "CFN_VERBOSE_ERRORS",
    "CI",
    "CUSTOM_SSL_CERT_PATH",
    "DEBUG",
    "DEBUG_HANDLER_CHAIN",
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
    "DYNAMODB_REMOVE_EXPIRED_ITEMS",
    "DYNAMODB_WRITE_ERROR_PROBABILITY",
    "EAGER_SERVICE_LOADING",
    "ENABLE_CONFIG_UPDATES",
    "EXTRA_CORS_ALLOWED_HEADERS",
    "EXTRA_CORS_ALLOWED_ORIGINS",
    "EXTRA_CORS_EXPOSE_HEADERS",
    "GATEWAY_LISTEN",
    "GATEWAY_SERVER",
    "GATEWAY_WORKER_THREAD_COUNT",
    "HOSTNAME",
    "HOSTNAME_FROM_LAMBDA",
    "KINESIS_ERROR_PROBABILITY",
    "KINESIS_MOCK_PERSIST_INTERVAL",
    "KINESIS_MOCK_LOG_LEVEL",
    "KINESIS_ON_DEMAND_STREAM_COUNT_LIMIT",
    "KINESIS_PERSISTENCE",
    "LAMBDA_DISABLE_AWS_ENDPOINT_URL",
    "LAMBDA_DOCKER_DNS",
    "LAMBDA_DOCKER_FLAGS",
    "LAMBDA_DOCKER_NETWORK",
    "LAMBDA_EVENTS_INTERNAL_SQS",
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
    "LAMBDA_REMOVE_CONTAINERS",
    "LAMBDA_RUNTIME_EXECUTOR",
    "LAMBDA_RUNTIME_ENVIRONMENT_TIMEOUT",
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
    "LAMBDA_LIMITS_MAX_FUNCTION_PAYLOAD_SIZE_BYTES",
    "LAMBDA_SQS_EVENT_SOURCE_MAPPING_INTERVAL",
    "LEGACY_DOCKER_CLIENT",
    "LEGACY_SNS_GCM_PUBLISHING",
    "LOCALSTACK_API_KEY",
    "LOCALSTACK_AUTH_TOKEN",
    "LOCALSTACK_HOST",
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
    "SQS_ENABLE_MESSAGE_RETENTION_PERIOD",
    "SQS_ENDPOINT_STRATEGY",
    "SQS_DISABLE_CLOUDWATCH_METRICS",
    "SQS_CLOUDWATCH_METRICS_REPORT_INTERVAL",
    "STEPFUNCTIONS_LAMBDA_ENDPOINT",
    "STRICT_SERVICE_LOADING",
    "TF_COMPAT_MODE",
    "USE_SSL",
    "WAIT_FOR_DEBUGGER",
    "WINDOWS_DOCKER_MOUNT_PREFIX",
    # Removed legacy variables in 2.0.0
    # DATA_DIR => do *not* include in this list, as it is treated separately.  # deprecated since 1.0.0
    "LEGACY_DIRECTORIES",  # deprecated since 1.0.0
    "SYNCHRONOUS_API_GATEWAY_EVENTS",  # deprecated since 1.3.0
    "SYNCHRONOUS_DYNAMODB_EVENTS",  # deprecated since 1.3.0
    "SYNCHRONOUS_SNS_EVENTS",  # deprecated since 1.3.0
    "SYNCHRONOUS_SQS_EVENTS",  # deprecated since 1.3.0
    # Removed legacy variables in 3.0.0
    "DEFAULT_REGION",  # deprecated since 0.12.7
    "EDGE_BIND_HOST",  # deprecated since 2.0.0
    "EDGE_FORWARD_URL",  # deprecated since 1.4.0
    "EDGE_PORT",  # deprecated since 2.0.0
    "EDGE_PORT_HTTP",  # deprecated since 2.0.0
    "ES_CUSTOM_BACKEND",  # deprecated since 0.14.0
    "ES_ENDPOINT_STRATEGY",  # deprecated since 0.14.0
    "ES_MULTI_CLUSTER",  # deprecated since 0.14.0
    "HOSTNAME_EXTERNAL",  # deprecated since 2.0.0
    "KINESIS_INITIALIZE_STREAMS",  # deprecated since 1.4.0
    "KINESIS_PROVIDER",  # deprecated since 1.3.0
    "KMS_PROVIDER",  # deprecated since 1.4.0
    "LAMBDA_XRAY_INIT",  # deprecated since 2.0.0
    "LAMBDA_CODE_EXTRACT_TIME",  # deprecated since 2.0.0
    "LAMBDA_CONTAINER_REGISTRY",  # deprecated since 2.0.0
    "LAMBDA_EXECUTOR",  # deprecated since 2.0.0
    "LAMBDA_FALLBACK_URL",  # deprecated since 2.0.0
    "LAMBDA_FORWARD_URL",  # deprecated since 2.0.0
    "LAMBDA_JAVA_OPTS",  # currently only supported in old Lambda provider but not officially deprecated
    "LAMBDA_REMOTE_DOCKER",  # deprecated since 2.0.0
    "LAMBDA_STAY_OPEN_MODE",  # deprecated since 2.0.0
    "LEGACY_EDGE_PROXY",  # deprecated since 1.0.0
    "LOCALSTACK_HOSTNAME",  # deprecated since 2.0.0
    "SQS_PORT_EXTERNAL",  # deprecated only in docs since 2022-07-13
    "SYNCHRONOUS_KINESIS_EVENTS",  # deprecated since 1.3.0
    "USE_SINGLE_REGION",  # deprecated since 0.12.7
    "MOCK_UNIMPLEMENTED",  # deprecated since 1.3.0
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

    # create variable aliases prefixed with LOCALSTACK_ (except LOCALSTACK_HOST)
    CONFIG_ENV_VARS += [
        "LOCALSTACK_" + v for v in CONFIG_ENV_VARS if not v.startswith("LOCALSTACK_")
    ]

    CONFIG_ENV_VARS = list(set(CONFIG_ENV_VARS))


# populate env var names to be passed to the container
populate_config_env_var_names()


# helpers to build urls
def get_protocol() -> str:
    return "https" if USE_SSL else "http"


def external_service_url(
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    subdomains: Optional[str] = None,
) -> str:
    """Returns a service URL (e.g., SQS queue URL) to an external client (e.g., boto3) potentially running on another
    machine than LocalStack. The configurations LOCALSTACK_HOST and USE_SSL can customize these returned URLs.
    The optional parameters can be used to customize the defaults.
    Examples with default configuration:
    * external_service_url() == http://localhost.localstack.cloud:4566
    * external_service_url(subdomains="s3") == http://s3.localhost.localstack.cloud:4566
    """
    protocol = protocol or get_protocol()
    subdomains = f"{subdomains}." if subdomains else ""
    host = host or LOCALSTACK_HOST.host
    port = port or LOCALSTACK_HOST.port
    return f"{protocol}://{subdomains}{host}:{port}"


def internal_service_url(
    host: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    subdomains: Optional[str] = None,
) -> str:
    """Returns a service URL for internal use within LocalStack (i.e., same host).
    The configuration USE_SSL can customize these returned URLs but LOCALSTACK_HOST has no effect.
    The optional parameters can be used to customize the defaults.
    Examples with default configuration:
    * internal_service_url() == http://localhost:4566
    * internal_service_url(port=8080) == http://localhost:8080
    """
    protocol = protocol or get_protocol()
    subdomains = f"{subdomains}." if subdomains else ""
    host = host or LOCALHOST
    port = port or GATEWAY_LISTEN[0].port
    return f"{protocol}://{subdomains}{host}:{port}"


# DEPRECATED: old helpers for building URLs


def service_url(service_key, host=None, port=None):
    """@deprecated: Use `internal_service_url()` instead. We assume that most usages are internal
    but really need to check and update each usage accordingly.
    """
    warnings.warn(
        """@deprecated: Use `internal_service_url()` instead. We assume that most usages are
        internal but really need to check and update each usage accordingly.""",
        DeprecationWarning,
    )
    return internal_service_url(host=host, port=port)


def service_port(service_key: str, external: bool = False) -> int:
    """@deprecated: Use `localstack_host().port` for external and `GATEWAY_LISTEN[0].port` for
    internal use."""
    warnings.warn(
        "Deprecated: use `localstack_host().port` for external and `GATEWAY_LISTEN[0].port` for "
        "internal use.",
        DeprecationWarning,
    )
    if external:
        return LOCALSTACK_HOST.port
    return GATEWAY_LISTEN[0].port


def get_edge_port_http():
    """@deprecated: Use `localstack_host().port` for external and `GATEWAY_LISTEN[0].port` for
    internal use. This function is also not needed anymore because we don't separate between HTTP
    and HTTP ports anymore since LocalStack listens to both."""
    warnings.warn(
        """@deprecated: Use `localstack_host().port` for external and `GATEWAY_LISTEN[0].port`
        for internal use. This function is also not needed anymore because we don't separate
        between HTTP and HTTP ports anymore since LocalStack listens to both.""",
        DeprecationWarning,
    )
    return GATEWAY_LISTEN[0].port


def get_edge_url(localstack_hostname=None, protocol=None):
    """@deprecated: Use `internal_service_url()` instead.
    We assume that most usages are internal but really need to check and update each usage accordingly.
    """
    warnings.warn(
        """@deprecated: Use `internal_service_url()` instead.
    We assume that most usages are internal but really need to check and update each usage accordingly.
    """,
        DeprecationWarning,
    )
    return internal_service_url(host=localstack_hostname, protocol=protocol)


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
