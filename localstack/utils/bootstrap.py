import functools
import logging
import os
import re
import shlex
import signal
import threading
import time
from functools import wraps
from typing import Dict, Iterable, List, Optional, Set

from localstack import config, constants
from localstack.config import Directories
from localstack.constants import DEFAULT_VOLUME_DIR
from localstack.runtime import hooks
from localstack.utils.container_networking import get_main_container_name
from localstack.utils.container_utils.container_client import (
    ContainerException,
    PortMappings,
    SimpleVolumeBind,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import cache_dir, chmod_r, mkdir
from localstack.utils.functions import call_safe
from localstack.utils.run import run, to_str
from localstack.utils.serving import Server
from localstack.utils.sync import poll_condition
from localstack.utils.tail import FileListener

LOG = logging.getLogger(__name__)

# maps from API names to list of other API names that they depend on
API_DEPENDENCIES = {
    "dynamodb": ["dynamodbstreams"],
    "dynamodbstreams": ["kinesis"],
    "es": ["opensearch"],
    "lambda": ["logs", "cloudwatch"],
    "kinesis": ["dynamodb"],
    "firehose": ["kinesis"],
}
# composites define an abstract name like "serverless" that maps to a set of services
API_COMPOSITES = {
    "serverless": [
        "cloudformation",
        "cloudwatch",
        "iam",
        "sts",
        "lambda",
        "dynamodb",
        "apigateway",
        "s3",
    ],
    "cognito": ["cognito-idp", "cognito-identity"],
}

# main container name determined via "docker inspect"
MAIN_CONTAINER_NAME_CACHED = None

# environment variable that indicates that we're executing in
# the context of the script that starts the Docker container
ENV_SCRIPT_STARTING_DOCKER = "LS_SCRIPT_STARTING_DOCKER"


def log_duration(name=None, min_ms=500):
    """Function decorator to log the duration of function invocations."""

    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            from time import perf_counter

            start_time = perf_counter()
            try:
                return f(*args, **kwargs)
            finally:
                end_time = perf_counter()
                func_name = name or f.__name__
                duration = (end_time - start_time) * 1000
                if duration > min_ms:
                    LOG.info('Execution of "%s" took %.2fms', func_name, duration)

        return wrapped

    return wrapper


def get_docker_image_details(image_name: str = None) -> Dict[str, str]:
    image_name = image_name or get_docker_image_to_start()
    try:
        result = DOCKER_CLIENT.inspect_image(image_name)
    except ContainerException:
        return {}
    result = {
        "id": result["Id"].replace("sha256:", "")[:12],
        "tag": (result.get("RepoTags") or ["latest"])[0].split(":")[-1],
        "created": result["Created"].split(".")[0],
    }
    return result


def get_image_environment_variable(env_name: str) -> Optional[str]:
    image_name = get_docker_image_to_start()
    image_info = DOCKER_CLIENT.inspect_image(image_name)
    image_envs = image_info["Config"]["Env"]

    try:
        found_env = next(env for env in image_envs if env.startswith(env_name))
    except StopIteration:
        return None
    return found_env.split("=")[1]


def get_server_version_from_running_container() -> str:
    try:
        # try to extract from existing running container
        container_name = get_main_container_name()
        version, _ = DOCKER_CLIENT.exec_in_container(
            container_name, interactive=True, command=["bin/localstack", "--version"]
        )
        version = to_str(version).strip().splitlines()[-1]
        return version
    except ContainerException:
        try:
            # try to extract by starting a new container
            img_name = get_docker_image_to_start()
            version, _ = DOCKER_CLIENT.run_container(
                img_name,
                remove=True,
                interactive=True,
                entrypoint="",
                command=["bin/localstack", "--version"],
            )
            version = to_str(version).strip().splitlines()[-1]
            return version
        except ContainerException:
            # fall back to default constant
            return constants.VERSION


def get_server_version() -> str:
    image_hash = get_docker_image_details()["id"]
    version_cache = cache_dir() / "image_metadata" / image_hash / "localstack_version"
    if version_cache.exists():
        cached_version = version_cache.read_text()
        return cached_version.strip()

    env_version = get_image_environment_variable("LOCALSTACK_BUILD_VERSION")
    if env_version is not None:
        version_cache.parent.mkdir(exist_ok=True, parents=True)
        version_cache.write_text(env_version)
        return env_version

    container_version = get_server_version_from_running_container()
    version_cache.parent.mkdir(exist_ok=True, parents=True)
    version_cache.write_text(container_version)

    return container_version


def setup_logging():
    """Determine and set log level. The singleton factory makes sure the logging is only set up once."""
    from localstack.logging.setup import setup_logging_from_config

    setup_logging_from_config()


# --------------
# INFRA STARTUP
# --------------


def resolve_apis(services: Iterable[str]) -> Set[str]:
    """
    Resolves recursively for the given collection of services (e.g., ["serverless", "cognito"]) the list of actual
    API services that need to be included (e.g., {'dynamodb', 'cloudformation', 'logs', 'kinesis', 'sts',
    'cognito-identity', 's3', 'dynamodbstreams', 'apigateway', 'cloudwatch', 'lambda', 'cognito-idp', 'iam'}).

    More specifically, it does this by:
    (1) resolving and adding dependencies (e.g., "dynamodbstreams" requires "kinesis"),
    (2) resolving and adding composites (e.g., "serverless" describes an ensemble
            including "iam", "lambda", "dynamodb", "apigateway", "s3", "sns", and "logs"), and
    (3) removing duplicates from the list.

    :param services: a collection of services that can include composites (e.g., "serverless").
    :returns a set of canonical service names
    """
    stack = []
    result = set()

    # perform a graph search
    stack.extend(services)
    while stack:
        service = stack.pop()

        if service in result:
            continue

        # resolve composites (like "serverless"), but do not add it to the list of results
        if service in API_COMPOSITES:
            stack.extend(API_COMPOSITES[service])
            continue

        result.add(service)

        # add dependencies to stack
        if service in API_DEPENDENCIES:
            stack.extend(API_DEPENDENCIES[service])

    return result


@functools.lru_cache()
def get_enabled_apis() -> Set[str]:
    """
    Returns the list of APIs that are enabled through the SERVICES variable. If the SERVICES variable is empty,
    then it will return all available services. Meta-services like "serverless" or "cognito", and dependencies are
    resolved.

    The result is cached, so it's safe to call. Clear the cache with get_enabled_apis.cache_clear().
    """
    return resolve_apis(config.parse_service_ports().keys())


def canonicalize_api_names(apis: Iterable[str] = None) -> List[str]:
    """
    Finalize the list of API names and SERVICE_PORT configurations by first resolving the real services from the
    enabled services, and then populating the configuration appropriately.

    """
    apis = resolve_apis(apis or config.SERVICE_PORTS.keys())

    # make sure we have port mappings for each API
    for api in apis:
        if api not in config.SERVICE_PORTS:
            config.SERVICE_PORTS[api] = config.DEFAULT_SERVICE_PORTS.get(api)

    return list(apis)


# DEPRECATED, lazy loading should be assumed
def is_api_enabled(api: str) -> bool:
    apis = get_enabled_apis()

    if api in apis:
        return True

    for enabled_api in apis:
        if api.startswith("%s:" % enabled_api):
            return True

    return False


def start_infra_locally():
    from localstack.services import infra

    return infra.start_infra()


def validate_localstack_config(name):
    # TODO: separate functionality from CLI output
    #  (use exceptions to communicate errors, and return list of warnings)
    from subprocess import CalledProcessError

    from localstack.cli import console

    dirname = os.getcwd()
    compose_file_name = name if os.path.isabs(name) else os.path.join(dirname, name)
    warns = []

    # validating docker-compose file
    cmd = ["docker-compose", "-f", compose_file_name, "config"]
    try:
        run(cmd, shell=False, print_error=False)
    except CalledProcessError as e:
        msg = f"{e}\n{to_str(e.output)}".strip()
        raise ValueError(msg)

    # validating docker-compose variable
    import yaml  # keep import here to avoid issues in test Lambdas

    with open(compose_file_name) as file:
        compose_content = yaml.full_load(file)
    services_config = compose_content.get("services", {})
    ls_service_name = [
        name for name, svc in services_config.items() if "localstack" in svc.get("image", "")
    ]
    if not ls_service_name:
        raise Exception(
            'No LocalStack service found in config (looking for image names containing "localstack")'
        )
    if len(ls_service_name) > 1:
        warns.append(f"Multiple candidates found for LocalStack service: {ls_service_name}")
    ls_service_name = ls_service_name[0]
    ls_service_details = services_config[ls_service_name]
    image_name = ls_service_details.get("image", "")
    if image_name.split(":")[0] not in constants.OFFICIAL_IMAGES:
        warns.append(
            'Using custom image "%s", we recommend using an official image: %s'
            % (image_name, constants.OFFICIAL_IMAGES)
        )

    # prepare config options
    image_name = ls_service_details.get("image")
    container_name = ls_service_details.get("container_name") or ""
    docker_ports = (port.split(":")[-2] for port in ls_service_details.get("ports", []))
    docker_env = dict(
        (env.split("=")[0], env.split("=")[1]) for env in ls_service_details.get("environment", {})
    )
    edge_port = str(docker_env.get("EDGE_PORT") or config.EDGE_PORT)
    main_container = config.MAIN_CONTAINER_NAME

    # docker-compose file validation cases

    if (main_container not in container_name) and not docker_env.get("MAIN_CONTAINER_NAME"):
        warns.append(
            'Please use "container_name: %s" or add "MAIN_CONTAINER_NAME" in "environment".'
            % main_container
        )

    def port_exposed(port):
        for exposed in docker_ports:
            if re.match(r"^([0-9]+-)?%s(-[0-9]+)?$" % port, exposed):
                return True

    if not port_exposed(edge_port):
        warns.append(
            (
                "Edge port %s is not exposed. You may have to add the entry "
                'to the "ports" section of the docker-compose file.'
            )
            % edge_port
        )

    # print warning/info messages
    for warning in warns:
        console.print("[yellow]:warning:[/yellow]", warning)
    if not warns:
        return True
    return False


def get_docker_image_to_start():
    image_name = os.environ.get("IMAGE_NAME")
    if not image_name:
        image_name = constants.DOCKER_IMAGE_NAME
        if os.environ.get("USE_LIGHT_IMAGE") in constants.FALSE_STRINGS:
            # FIXME deprecated - remove with 2.0
            LOG.warning(
                "USE_LIGHT_IMAGE is deprecated (since 1.3.0) and will be removed in upcoming releases of LocalStack! "
                "The localstack/localstack-full image is deprecated. Please remove this environment variable."
            )
            image_name = constants.DOCKER_IMAGE_NAME_FULL
        if is_api_key_configured():
            image_name = constants.DOCKER_IMAGE_NAME_PRO
    return image_name


def extract_port_flags(user_flags, port_mappings: PortMappings):
    regex = r"-p\s+([0-9]+)(\-([0-9]+))?:([0-9]+)(\-([0-9]+))?"
    matches = re.match(".*%s" % regex, user_flags)
    if matches:
        for match in re.findall(regex, user_flags):
            start = int(match[0])
            end = int(match[2] or match[0])
            start_target = int(match[3] or start)
            end_target = int(match[5] or end)
            port_mappings.add([start, end], [start_target, end_target])
        user_flags = re.sub(regex, r"", user_flags)
    return user_flags


# TODO merge with docker_utils.py:ContainerConfiguration
class LocalstackContainer:
    name: str
    image_name: str
    volumes: VolumeMappings
    ports: PortMappings
    entrypoint: str
    additional_flags: List[str]
    command: List[str]

    privileged: bool = True
    remove: bool = True
    interactive: bool = False
    tty: bool = False
    detach: bool = False
    inherit_env: bool = True

    logfile: Optional[str] = None
    stdin: Optional[str] = None
    user: Optional[str] = None
    cap_add: Optional[List[str]] = None
    network: Optional[str] = None
    dns: Optional[str] = None
    workdir: Optional[str] = None

    def __init__(self, name: str = None):
        self.name = name or config.MAIN_CONTAINER_NAME
        self.entrypoint = os.environ.get("ENTRYPOINT", "")
        self.command = shlex.split(os.environ.get("CMD", ""))
        self.image_name = get_docker_image_to_start()
        self.ports = PortMappings(bind_host=config.EDGE_BIND_HOST)
        self.volumes = VolumeMappings()
        self.env_vars = {}
        self.additional_flags = []

        self.logfile = os.path.join(config.dirs.tmp, f"{self.name}_container.log")

    def _get_mount_volumes(self) -> List[SimpleVolumeBind]:
        # FIXME: VolumeMappings should be supported by the docker client
        mount_volumes = []
        for volume in self.volumes:
            if isinstance(volume, tuple):
                mount_volumes.append(volume)
            elif isinstance(volume, VolumeBind):
                mount_volumes.append((volume.host_dir, volume.container_dir))
            else:
                raise NotImplementedError("no support for volume type %s" % type(volume))

        return mount_volumes

    def run(self):
        if isinstance(DOCKER_CLIENT, CmdDockerClient):
            DOCKER_CLIENT.default_run_outfile = self.logfile

        try:
            return DOCKER_CLIENT.run_container(
                image_name=self.image_name,
                stdin=self.stdin,
                name=self.name,
                entrypoint=self.entrypoint or None,
                remove=self.remove,
                interactive=self.interactive,
                tty=self.tty,
                detach=self.detach,
                command=self.command or None,
                mount_volumes=self._get_mount_volumes(),
                ports=self.ports,
                env_vars=self.env_vars,
                user=self.user,
                cap_add=self.cap_add,
                network=self.network,
                dns=self.dns,
                additional_flags=" ".join(self.additional_flags),
                workdir=self.workdir,
                privileged=self.privileged,
            )
        except ContainerException as e:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.exception("Error while starting LocalStack container")
            else:
                LOG.error(
                    "Error while starting LocalStack container: %s\n%s", e.message, to_str(e.stderr)
                )
            raise

    def truncate_log(self):
        with open(self.logfile, "wb") as fd:
            fd.write(b"")


class LocalstackContainerServer(Server):
    container: LocalstackContainer

    def __init__(self, container=None) -> None:
        super().__init__(config.EDGE_PORT, config.EDGE_BIND_HOST)
        self.container = container or LocalstackContainer()

    def is_up(self) -> bool:
        """
        Checks whether the container is running, and the Ready marker has been printed to the logs.
        """

        if not self.is_container_running():
            return False
        logs = DOCKER_CLIENT.get_container_logs(self.container.name)

        if constants.READY_MARKER_OUTPUT not in logs.splitlines():
            return False
        # also checks the edge port health status
        return super().is_up()

    def is_container_running(self) -> bool:
        return DOCKER_CLIENT.is_container_running(self.container.name)

    def wait_is_container_running(self, timeout=None) -> bool:
        return poll_condition(self.is_container_running, timeout)

    def do_run(self):
        if DOCKER_CLIENT.is_container_running(self.container.name):
            raise ContainerExists(
                'LocalStack container named "%s" is already running' % self.container.name
            )

        return self.container.run()

    def do_shutdown(self):
        try:
            DOCKER_CLIENT.stop_container(
                self.container.name, timeout=10
            )  # giving the container some time to stop
        except Exception as e:
            LOG.info("error cleaning up localstack container %s: %s", self.container.name, e)


class ContainerExists(Exception):
    pass


def prepare_docker_start():
    # prepare environment for docker start
    container_name = config.MAIN_CONTAINER_NAME

    if DOCKER_CLIENT.is_container_running(container_name):
        raise ContainerExists('LocalStack container named "%s" is already running' % container_name)
    if config.dirs.tmp != config.dirs.functions and not config.LAMBDA_REMOTE_DOCKER:
        # Logger is not initialized at this point, so the warning is displayed via print
        print(
            f"WARNING: The detected temp folder for localstack ({config.dirs.tmp}) is not equal to the "
            f"HOST_TMP_FOLDER environment variable set ({config.dirs.functions})."
        )

    os.environ[ENV_SCRIPT_STARTING_DOCKER] = "1"

    # make sure temp folder exists
    mkdir(config.dirs.tmp)
    try:
        chmod_r(config.dirs.tmp, 0o777)
    except Exception:
        pass


def configure_container(container: LocalstackContainer):
    """
    Configuration routine for the LocalstackContainer.
    """
    # get additional configured flags
    user_flags = config.DOCKER_FLAGS
    user_flags = extract_port_flags(user_flags, container.ports)
    container.additional_flags.extend(shlex.split(user_flags))

    # get additional parameters from plugins
    hooks.configure_localstack_container.run(container)

    # construct default port mappings
    service_ports = config.SERVICE_PORTS
    if service_ports.get("edge") == 0:
        service_ports.pop("edge")
    for port in service_ports.values():
        if port:
            container.ports.add(port)
    for port in range(config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END):
        container.ports.add(port)

    if config.DEVELOP:
        container.ports.add(config.DEVELOP_PORT)

    # environment variables
    # pass through environment variables defined in config
    for env_var in config.CONFIG_ENV_VARS:
        value = os.environ.get(env_var, None)
        if value is not None:
            container.env_vars[env_var] = value
    container.env_vars["DOCKER_HOST"] = f"unix://{config.DOCKER_SOCK}"

    # TODO this is default now, remove once a considerate time is passed
    # to activate proper signal handling
    container.env_vars["SET_TERM_HANDLER"] = "1"

    configure_volume_mounts(container)

    # mount docker socket
    container.volumes.append((config.DOCKER_SOCK, config.DOCKER_SOCK))

    container.privileged = True


def configure_volume_mounts(container: LocalstackContainer):
    if not config.LEGACY_DIRECTORIES:
        container.volumes.add(VolumeBind(config.VOLUME_DIR, DEFAULT_VOLUME_DIR))
        return

    source_dirs = config.dirs
    target_dirs = Directories.legacy_for_container()

    # default shared directories
    for name in Directories.default_bind_mounts:
        src = getattr(source_dirs, name, None)
        target = getattr(target_dirs, name, None)
        if src and target:
            container.volumes.add(VolumeBind(src, target))

    # shared tmp folder
    container.volumes.add(VolumeBind(source_dirs.tmp, target_dirs.tmp))

    # set the HOST_TMP_FOLDER for the legacy dirs / legacy lambda function mounting
    container.env_vars["HOST_TMP_FOLDER"] = source_dirs.functions

    # data_dir mounting and environment variables
    if source_dirs.data:
        container.volumes.add(VolumeBind(source_dirs.data, target_dirs.data))
        container.env_vars["DATA_DIR"] = target_dirs.data


@log_duration()
def prepare_host(console):
    """
    Prepare the host environment for running LocalStack, this should be called before start_infra_*.
    """
    if os.environ.get(constants.LOCALSTACK_INFRA_PROCESS) in constants.TRUE_STRINGS:
        return

    try:
        mkdir(config.VOLUME_DIR)
    except Exception as e:
        console.print(f"Error while creating volume dir {config.VOLUME_DIR}: {e}")
        if config.DEBUG:
            console.print_exception()

    setup_logging()
    hooks.prepare_host.run()


def start_infra_in_docker():
    prepare_docker_start()

    container = LocalstackContainer()

    # create and prepare container
    configure_container(container)

    container.truncate_log()

    # printing the container log is the current way we're occupying the terminal
    log_printer = FileListener(container.logfile, print)
    log_printer.start()

    # Set up signal handler, to enable clean shutdown across different operating systems.
    #  There are subtle differences across operating systems and terminal emulators when it
    #  comes to handling of CTRL-C - in particular, Linux sends SIGINT to the parent process,
    #  whereas MacOS sends SIGINT to the process group, which can result in multiple SIGINT signals
    #  being received (e.g., when running the localstack CLI as part of a "npm run .." script).
    #  Hence, using a shutdown handler and synchronization event here, to avoid inconsistencies.
    def shutdown_handler(*args):
        with shutdown_event_lock:
            if shutdown_event.is_set():
                return
            shutdown_event.set()
        print("Shutting down...")
        server.shutdown()
        log_printer.close()

    shutdown_event = threading.Event()
    shutdown_event_lock = threading.RLock()
    signal.signal(signal.SIGINT, shutdown_handler)

    # start the Localstack container as a Server
    server = LocalstackContainerServer(container)
    try:
        server.start()
        server.join()
    except KeyboardInterrupt:
        print("ok, bye!")
        shutdown_handler()


def start_infra_in_docker_detached(console):
    """
    An alternative to start_infra_in_docker where the terminal is not blocked by the follow on the logfile.
    """
    console.log("preparing environment")
    try:
        prepare_docker_start()
    except ContainerExists as e:
        console.print(str(e))
        return

    # create and prepare container
    console.log("configuring container")
    container = LocalstackContainer()
    configure_container(container)
    container.detach = True
    container.truncate_log()

    # start the Localstack container as a Server
    console.log("starting container")
    server = LocalstackContainerServer(container)
    server.start()
    server.wait_is_container_running()
    console.log("detaching")


def wait_container_is_ready(timeout: Optional[float] = None):
    """Blocks until the localstack main container is running and the ready marker has been printed."""
    container_name = config.MAIN_CONTAINER_NAME
    started = time.time()

    def is_container_running():
        return DOCKER_CLIENT.is_container_running(container_name)

    if not poll_condition(is_container_running, timeout=timeout):
        return False

    stream = DOCKER_CLIENT.stream_container_logs(container_name)

    # create a timer that will terminate the log stream after the remaining timeout
    timer = None
    if timeout:
        waited = time.time() - started
        remaining = timeout - waited
        # check the rare case that the timeout has already been reached
        if remaining <= 0:
            stream.close()
            return False
        timer = threading.Timer(remaining, stream.close)
        timer.start()

    try:
        for line in stream:
            line = line.decode("utf-8").strip()
            if line == constants.READY_MARKER_OUTPUT:
                return True

        # EOF was reached or the stream was closed
        return False
    finally:
        call_safe(stream.close)
        if timer:
            # make sure the timer is stopped (does nothing if it has already run)
            timer.cancel()


# ---------------
# UTIL FUNCTIONS
# ---------------


def in_ci():
    """Whether or not we are running in a CI environment"""
    for key in ("CI", "TRAVIS"):
        if os.environ.get(key, "") not in [False, "", "0", "false"]:
            return True
    return False


def is_api_key_configured() -> bool:
    """Whether an API key is set in the environment."""
    return (
        True
        if os.environ.get("LOCALSTACK_API_KEY") and os.environ.get("LOCALSTACK_API_KEY").strip()
        else False
    )
