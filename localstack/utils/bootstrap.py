from __future__ import annotations

import copy
import functools
import logging
import os
import re
import shlex
import signal
import threading
import time
from functools import wraps
from typing import Any, Dict, Iterable, Optional, Set

from localstack import config, constants
from localstack.config import get_edge_port_http, is_env_true
from localstack.constants import DEFAULT_VOLUME_DIR
from localstack.runtime import hooks
from localstack.utils.container_networking import get_main_container_name
from localstack.utils.container_utils.container_client import (
    ContainerConfiguration,
    ContainerException,
    NoSuchImage,
    NoSuchNetwork,
    PortMappings,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.files import cache_dir, mkdir
from localstack.utils.functions import call_safe
from localstack.utils.run import is_command_available, run, to_str
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
    services_env = os.environ.get("SERVICES", "").strip()
    services = None
    if services_env and not is_env_true("EAGER_SERVICE_LOADING"):
        LOG.warning("SERVICES variable is ignored if EAGER_SERVICE_LOADING=0.")
    elif services_env:
        # SERVICES and EAGER_SERVICE_LOADING are set
        # SERVICES env var might contain ports, but we do not support these anymore
        services = []
        for service_port in re.split(r"\s*,\s*", services_env):
            # Only extract the service name, discard the port
            parts = re.split(r"[:=]", service_port)
            service = parts[0]
            services.append(service)

    if not services:
        from localstack.services.plugins import SERVICE_PLUGINS

        services = SERVICE_PLUGINS.list_available()

    return resolve_apis(services)


# DEPRECATED, lazy loading should be assumed
def is_api_enabled(api: str) -> bool:
    apis = get_enabled_apis()

    if api in apis:
        return True

    for enabled_api in apis:
        if api.startswith(f"{enabled_api}:"):
            return True

    return False


def start_infra_locally():
    from localstack.services import infra

    return infra.start_infra()


def validate_localstack_config(name: str):
    # TODO: separate functionality from CLI output
    #  (use exceptions to communicate errors, and return list of warnings)
    from subprocess import CalledProcessError

    from localstack.cli import console

    dirname = os.getcwd()
    compose_file_name = name if os.path.isabs(name) else os.path.join(dirname, name)
    warns = []

    # some systems do not have "docker-compose" aliased to "docker compose", and older systems do not have
    # "docker compose" at all. By preferring the old way and falling back on the new, we should get docker compose in
    # any way, if installed
    if is_command_available("docker-compose"):
        compose_command = ["docker-compose"]
    else:
        compose_command = ["docker", "compose"]
    # validating docker-compose file
    cmd = [*compose_command, "-f", compose_file_name, "config"]
    try:
        run(cmd, shell=False, print_error=False)
    except CalledProcessError as e:
        msg = f"{e}\n{to_str(e.output)}".strip()
        raise ValueError(msg)

    import yaml  # keep import here to avoid issues in test Lambdas

    # validating docker-compose variable
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
            f'Using custom image "{image_name}", we recommend using an official image: {constants.OFFICIAL_IMAGES}'
        )

    # prepare config options
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
            f'Please use "container_name: {main_container}" or add "MAIN_CONTAINER_NAME" in "environment".'
        )

    def port_exposed(port):
        for exposed in docker_ports:
            if re.match(r"^([0-9]+-)?%s(-[0-9]+)?$" % port, exposed):
                return True

    if not port_exposed(edge_port):
        warns.append(
            (
                f"Edge port {edge_port} is not exposed. You may have to add the entry "
                'to the "ports" section of the docker-compose file.'
            )
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


class LocalstackContainer:
    config: ContainerConfiguration
    running_container: RunningLocalstackContainer | None

    def __init__(self, name: str = None):
        self.config = self._get_default_configuration(name)
        self.logfile = os.path.join(config.dirs.tmp, f"{self.config.name}_container.log")

        self.additional_flags = []  # TODO: see comment in run()

        # marker to access the running container
        self.running_container = None

    def truncate_log(self):
        with open(self.logfile, "wb") as fd:
            fd.write(b"")

    @staticmethod
    def _get_default_configuration(name: str = None) -> ContainerConfiguration:
        """Returns a ContainerConfiguration populated with default values or values gathered from the
        environment for starting the LocalStack container."""
        return ContainerConfiguration(
            image_name=get_docker_image_to_start(),
            name=name or config.MAIN_CONTAINER_NAME,
            volumes=VolumeMappings(),
            remove=True,
            # FIXME: update with https://github.com/localstack/localstack/pull/7991
            ports=PortMappings(bind_host=config.EDGE_BIND_HOST),
            entrypoint=os.environ.get("ENTRYPOINT"),
            command=shlex.split(os.environ.get("CMD", "")) or None,
            env_vars={},
        )

    def run(self, attach: bool = True) -> RunningLocalstackContainer:
        if isinstance(DOCKER_CLIENT, CmdDockerClient):
            DOCKER_CLIENT.default_run_outfile = self.logfile

        # FIXME: this is pretty awkward, but additional_flags in the LocalstackContainer API was always a
        #  list of ["-e FOO=BAR", ...], whereas in the DockerClient it is expected to be a string. so we
        #  need to re-assemble it here. the better way would be to not use additional_flags here all
        #  together. it is still used in ext in `configure_pro_container` which could be refactored to use
        #  the additional port bindings.
        cfg = copy.deepcopy(self.config)
        if not cfg.additional_flags:
            cfg.additional_flags = ""
        if self.additional_flags:
            cfg.additional_flags += " " + " ".join(self.additional_flags)

        # TODO: there could be a --network flag in `additional_flags`. we solve a similar problem for the
        #  ports using `extract_port_flags`. maybe it would be better to consolidate all this into the
        #  ContainerConfig object, like ContainerConfig.update_from_flags(str).
        self._ensure_container_network(cfg.network)

        try:
            id = DOCKER_CLIENT.create_container_from_config(cfg)
        except ContainerException as e:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.exception("Error while creating LocalStack container")
            else:
                LOG.error(
                    "Error while creating LocalStack container: %s\n%s", e.message, to_str(e.stderr)
                )
            raise

        running_container = RunningLocalstackContainer(
            id, container_config=self.config, logfile=self.logfile
        )
        running_container.start(attach=attach)
        return running_container

    @staticmethod
    def _ensure_container_network(network: str):
        """Makes sure the configured container network exists"""
        if network:
            if network in ["host", "bridge"]:
                return
            try:
                DOCKER_CLIENT.inspect_network(network)
            except NoSuchNetwork:
                LOG.debug("Container network %s not found, creating it", network)
                DOCKER_CLIENT.create_network(network)

    @property
    def env_vars(self) -> Dict[str, str]:
        return self.config.env_vars

    @property
    def entrypoint(self) -> Optional[str]:
        return self.config.entrypoint

    @entrypoint.setter
    def entrypoint(self, value: str):
        self.config.entrypoint = value

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def volumes(self) -> VolumeMappings:
        return self.config.volumes

    @property
    def ports(self) -> PortMappings:
        return self.config.ports


class RunningLocalstackContainer:
    """
    Represents a LocalStack container that is running.
    """

    id: str
    name: str
    container_config: ContainerConfiguration

    def __init__(self, id: str, container_config: ContainerConfiguration, logfile: str):
        self.id = id
        self.container_config = container_config
        self.logfile = logfile

        self.name = DOCKER_CLIENT.get_container_name(self.id)

    def start(self, attach: bool = False):
        try:
            return DOCKER_CLIENT.start_container(self.id, attach=attach)
        except ContainerException as e:
            LOG.error(
                "Error while starting LocalStack container: %s\n%s",
                e.message,
                to_str(e.stderr),
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise

    def shutdown(self):
        if not DOCKER_CLIENT.is_container_running(self.name):
            return

        DOCKER_CLIENT.stop_container(container_name=self.id, timeout=30)

    def truncate_log(self):
        with open(self.logfile, "wb") as fd:
            fd.write(b"")

    # these properties are there to not break code that configures the container by using these values
    # that code should ideally be refactored soon-ish to use the config instead.

    @property
    def env_vars(self) -> Dict[str, str]:
        return self.container_config.env_vars

    @property
    def entrypoint(self) -> Optional[str]:
        return self.container_config.entrypoint

    @entrypoint.setter
    def entrypoint(self, value: str):
        self.container_config.entrypoint = value

    @property
    def volumes(self) -> VolumeMappings:
        return self.container_config.volumes

    @property
    def ports(self) -> PortMappings:
        return self.container_config.ports

    def wait_until_ready(self, timeout: float | None = None):
        if self.id is None:
            raise ValueError("no container id found, cannot wait until ready")
        return poll_condition(self.is_container_running, timeout)

    def is_container_running(self) -> bool:
        logs = DOCKER_CLIENT.get_container_logs(self.id)
        return constants.READY_MARKER_OUTPUT in logs.splitlines()

    def exec_in_container(self, *args, **kwargs):
        return DOCKER_CLIENT.exec_in_container(container_name_or_id=self.id, *args, **kwargs)


class LocalstackContainerServer(Server):
    container: LocalstackContainer | RunningLocalstackContainer

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

        config.dirs.mkdirs()
        self.container = self.container.run()
        return self.container

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

    config.dirs.mkdirs()


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
    container.ports.add(get_edge_port_http())
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


def configure_container_from_cli_params(container: LocalstackContainer, params: Dict[str, Any]):
    # TODO: consolidate with container_client.Util.parse_additional_flags
    # network flag
    if params.get("network"):
        container.config.network = params.get("network")

    # parse environment variable flags
    if params.get("env"):
        for e in params.get("env"):
            if "=" in e:
                k, v = e.split("=", maxsplit=1)
                container.config.env_vars[k] = v
            else:
                # there's currently no way in our abstraction to only pass the variable name (as you can do
                # in docker) so we resolve the value here.
                container.config.env_vars[e] = os.getenv(e)


def configure_volume_mounts(container: LocalstackContainer):
    container.volumes.add(VolumeBind(config.VOLUME_DIR, DEFAULT_VOLUME_DIR))


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


def start_infra_in_docker(console, cli_params: Dict[str, Any] = None):
    prepare_docker_start()

    # create and prepare container
    container = LocalstackContainer()
    configure_container(container)
    if cli_params:
        configure_container_from_cli_params(container, cli_params or {})
    ensure_container_image(console, container)

    status = console.status("Starting LocalStack container")
    status.start()

    # printing the container log is the current way we're occupying the terminal
    def _init_log_printer(line):
        """Prints the console rule separator on the first line, then re-configures the callback to print."""
        status.stop()
        console.rule("LocalStack Runtime Log (press [bold][yellow]CTRL-C[/yellow][/bold] to quit)")
        print(line)
        log_printer.callback = print

    container.truncate_log()
    log_printer = FileListener(container.logfile, callback=_init_log_printer)
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
        error = server.get_error()
        if error:
            # if the server failed, raise the error
            raise error
    except KeyboardInterrupt:
        print("ok, bye!")
        shutdown_handler()


def ensure_container_image(console, container: LocalstackContainer):
    try:
        DOCKER_CLIENT.inspect_image(container.config.image_name, pull=False)
        return
    except NoSuchImage:
        console.log("container image not found on host")

    with console.status(f"Pulling container image {container.config.image_name}"):
        DOCKER_CLIENT.pull_image(container.config.image_name)
        console.log("download complete")


def start_infra_in_docker_detached(console, cli_params: Dict[str, Any] = None):
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
    if cli_params:
        configure_container_from_cli_params(container, cli_params)
    ensure_container_image(console, container)

    container.config.detach = True
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
