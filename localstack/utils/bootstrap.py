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
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Union

from localstack import config, constants
from localstack.config import HostAndPort, default_ip, is_env_not_false, is_env_true
from localstack.runtime import hooks
from localstack.utils.container_networking import get_main_container_name
from localstack.utils.container_utils.container_client import (
    CancellableStream,
    ContainerClient,
    ContainerConfiguration,
    ContainerConfigurator,
    ContainerException,
    NoSuchContainer,
    NoSuchImage,
    NoSuchNetwork,
    PortMappings,
    VolumeBind,
    VolumeMappings,
)
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.docker_utils import DOCKER_CLIENT, container_ports_can_be_bound
from localstack.utils.files import cache_dir, mkdir
from localstack.utils.functions import call_safe
from localstack.utils.net import Port, get_free_tcp_port, get_free_tcp_port_range
from localstack.utils.run import is_command_available, run, to_str
from localstack.utils.serving import Server
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)

# maps from API names to list of other API names that they depend on
API_DEPENDENCIES = {
    "dynamodb": ["dynamodbstreams"],
    "dynamodbstreams": ["kinesis"],
    "es": ["opensearch"],
    "cloudformation": ["s3", "sts"],
    "lambda": ["s3", "sqs", "sts"],
    "firehose": ["kinesis"],
    "transcribe": ["s3"],
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


def get_container_default_logfile_location(container_name: str) -> str:
    return os.path.join(config.dirs.mounted_tmp, f"{container_name}_container.log")


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
    Returns the list of APIs that are enabled through the combination of the SERVICES variable and
    STRICT_SERVICE_LOADING variable. If the SERVICES variable is empty, then it will return all available services.
    Meta-services like "serverless" or "cognito", and dependencies are resolved.

    The result is cached, so it's safe to call. Clear the cache with get_enabled_apis.cache_clear().
    """
    from localstack.services.plugins import SERVICE_PLUGINS

    services_env = os.environ.get("SERVICES", "").strip()
    services = SERVICE_PLUGINS.list_available()

    if services_env and is_env_not_false("STRICT_SERVICE_LOADING"):
        # SERVICES and STRICT_SERVICE_LOADING are set
        # we filter the result of SERVICE_PLUGINS.list_available() to cross the user-provided list with
        # the available ones
        enabled_services = []
        for service_port in re.split(r"\s*,\s*", services_env):
            # Only extract the service name, discard the port
            parts = re.split(r"[:=]", service_port)
            service = parts[0]
            enabled_services.append(service)

        services = [service for service in enabled_services if service in services]
        # TODO: log a message if a service was not supported? see with pro loading

    return resolve_apis(services)


def is_api_enabled(api: str) -> bool:
    return api in get_enabled_apis()


@functools.lru_cache()
def get_preloaded_services() -> Set[str]:
    """
    Returns the list of APIs that are marked to be eager loaded through the combination of SERVICES variable and
    EAGER_SERVICE_LOADING. If the SERVICES variable is empty, then it will return all available services.
    Meta-services like "serverless" or "cognito", and dependencies are resolved.

    The result is cached, so it's safe to call. Clear the cache with get_preloaded_services.cache_clear().
    """
    services_env = os.environ.get("SERVICES", "").strip()
    services = None

    if services_env and is_env_true("EAGER_SERVICE_LOADING"):
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


def should_eager_load_api(api: str) -> bool:
    apis = get_preloaded_services()

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
    edge_port = config.GATEWAY_LISTEN[0].port
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


class ContainerConfigurators:
    """
    A set of useful container configurators that are typical for starting the localstack container.
    """

    @staticmethod
    def mount_docker_socket(cfg: ContainerConfiguration):
        source = config.DOCKER_SOCK
        target = "/var/run/docker.sock"
        if cfg.volumes.find_target_mapping(target):
            return
        cfg.volumes.add(VolumeBind(source, target))
        cfg.env_vars["DOCKER_HOST"] = f"unix://{target}"

    @staticmethod
    def mount_localstack_volume(host_path: str | os.PathLike = None):
        host_path = host_path or config.VOLUME_DIR

        def _cfg(cfg: ContainerConfiguration):
            if cfg.volumes.find_target_mapping(constants.DEFAULT_VOLUME_DIR):
                return
            cfg.volumes.add(VolumeBind(str(host_path), constants.DEFAULT_VOLUME_DIR))

        return _cfg

    @staticmethod
    def config_env_vars(cfg: ContainerConfiguration):
        """Sets all env vars from config.CONFIG_ENV_VARS."""
        for env_var in config.CONFIG_ENV_VARS:
            value = os.environ.get(env_var, None)
            if value is not None:
                cfg.env_vars[env_var] = value

    @staticmethod
    def random_gateway_port(cfg: ContainerConfiguration):
        """Gets a random port on the host and maps it to the default edge port 4566."""
        return ContainerConfigurators.gateway_listen(get_free_tcp_port())(cfg)

    @staticmethod
    def default_gateway_port(cfg: ContainerConfiguration):
        """Adds 4566 to the list of port mappings"""
        return ContainerConfigurators.gateway_listen(constants.DEFAULT_PORT_EDGE)(cfg)

    @staticmethod
    def gateway_listen(
        port: Union[int, Iterable[int], HostAndPort, Iterable[HostAndPort]],
    ):
        """
        Uses the given ports to configure GATEWAY_LISTEN. For instance, ``gateway_listen([4566, 443])`` would
        result in the port mappings 4566:4566, 443:443, as well as ``GATEWAY_LISTEN=:4566,:443``.

        :param port: a single or list of ports, can either be int ports or HostAndPort instances
        :return: a configurator
        """
        if isinstance(port, int):
            ports = [HostAndPort("", port)]
        elif isinstance(port, HostAndPort):
            ports = [port]
        else:
            ports = []
            for p in port:
                if isinstance(p, int):
                    ports.append(HostAndPort("", p))
                else:
                    ports.append(p)

        def _cfg(cfg: ContainerConfiguration):
            for _p in ports:
                cfg.ports.add(_p.port)

            # gateway listen should be compiled s.t. even if we set "127.0.0.1:4566" from the host,
            # it will be correctly exposed on "0.0.0.0:4566" in the container.
            cfg.env_vars["GATEWAY_LISTEN"] = ",".join(
                [f"{p.host if p.host != default_ip else ''}:{p.port}" for p in ports]
            )

        return _cfg

    @staticmethod
    def publish_dns_ports(cfg: ContainerConfiguration):
        dns_ports = [
            Port(config.DNS_PORT, protocol="udp"),
            Port(config.DNS_PORT, protocol="tcp"),
        ]
        if container_ports_can_be_bound(dns_ports, address=config.DNS_ADDRESS):
            # expose the DNS server to the host
            # TODO: update ContainerConfiguration to support multiple PortMappings objects with different bind addresses
            docker_flags = []
            for port in dns_ports:
                docker_flags.extend(
                    [
                        "-p",
                        f"{config.DNS_ADDRESS}:{port.port}:{port.port}/{port.protocol}",
                    ]
                )
            if cfg.additional_flags is None:
                cfg.additional_flags = " ".join(docker_flags)
            else:
                cfg.additional_flags += " " + " ".join(docker_flags)

    @staticmethod
    def container_name(name: str):
        def _cfg(cfg: ContainerConfiguration):
            cfg.name = name
            cfg.env_vars["MAIN_CONTAINER_NAME"] = cfg.name

        return _cfg

    @staticmethod
    def random_container_name(cfg: ContainerConfiguration):
        cfg.name = f"localstack-{short_uid()}"
        cfg.env_vars["MAIN_CONTAINER_NAME"] = cfg.name

    @staticmethod
    def default_container_name(cfg: ContainerConfiguration):
        cfg.name = config.MAIN_CONTAINER_NAME
        cfg.env_vars["MAIN_CONTAINER_NAME"] = cfg.name

    @staticmethod
    def service_port_range(cfg: ContainerConfiguration):
        cfg.ports.add([config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END])
        cfg.env_vars["EXTERNAL_SERVICE_PORTS_START"] = config.EXTERNAL_SERVICE_PORTS_START
        cfg.env_vars["EXTERNAL_SERVICE_PORTS_END"] = config.EXTERNAL_SERVICE_PORTS_END

    @staticmethod
    def random_service_port_range(num: int = 50):
        """
        Tries to find a contiguous list of random ports on the host to map to the external service port
        range in the container.
        """

        def _cfg(cfg: ContainerConfiguration):
            port_range = get_free_tcp_port_range(num)
            cfg.ports.add([port_range.start, port_range.end])
            cfg.env_vars["EXTERNAL_SERVICE_PORTS_START"] = str(port_range.start)
            cfg.env_vars["EXTERNAL_SERVICE_PORTS_END"] = str(port_range.end)

        return _cfg

    @staticmethod
    def debug(cfg: ContainerConfiguration):
        cfg.env_vars["DEBUG"] = "1"

    @classmethod
    def develop(cls, cfg: ContainerConfiguration):
        cls.env_vars(
            {
                "DEVELOP": "1",
            }
        )(cfg)
        cls.port(5678)(cfg)

    @staticmethod
    def network(network: str):
        def _cfg(cfg: ContainerConfiguration):
            cfg.network = network

        return _cfg

    @staticmethod
    def custom_command(cmd: List[str]):
        """
        Overwrites the container command and unsets the default entrypoint.

        :param cmd: the command to run in the container
        :return: a configurator
        """

        def _cfg(cfg: ContainerConfiguration):
            cfg.command = cmd
            cfg.entrypoint = ""

        return _cfg

    @staticmethod
    def env_vars(env_vars: Dict[str, str]):
        def _cfg(cfg: ContainerConfiguration):
            cfg.env_vars.update(env_vars)

        return _cfg

    @staticmethod
    def port(*args, **kwargs):
        def _cfg(cfg: ContainerConfiguration):
            cfg.ports.add(*args, **kwargs)

        return _cfg

    @staticmethod
    def volume(volume: VolumeBind):
        def _cfg(cfg: ContainerConfiguration):
            cfg.volumes.add(volume)

        return _cfg

    @staticmethod
    def cli_params(params: Dict[str, Any]):
        """
        Parse docker CLI parameters and add them to the config. The currently known CLI params are::

            --network=my-network       <- stored in "network"
            -e FOO=BAR -e BAR=ed       <- stored in "env"
            -p 4566:4566 -p 4510-4559  <- stored in "publish"
            -v ./bar:/foo/bar          <- stored in "volume"

        When parsed by click, the parameters would look like this::

            {
                "network": "my-network",
                "env": ("FOO=BAR", "BAR=ed"),
                "publish": ("4566:4566", "4510-4559"),
                "volume": ("./bar:/foo/bar",),
            }

        :param params: a dict of parsed parameters
        :return: a configurator
        """

        # TODO: consolidate with container_client.Util.parse_additional_flags
        def _cfg(cfg: ContainerConfiguration):
            if params.get("network"):
                cfg.network = params.get("network")

            # processed parsed -e, -p, and -v flags
            ContainerConfigurators.env_cli_params(params.get("env"))(cfg)
            ContainerConfigurators.port_cli_params(params.get("publish"))(cfg)
            ContainerConfigurators.volume_cli_params(params.get("volume"))(cfg)

        return _cfg

    @staticmethod
    def env_cli_params(params: Iterable[str] = None):
        """
        Configures environment variables from additional CLI input through the ``-e`` options.

        :param params: a list of environment variable declarations, e.g.,: ``("foo=bar", "baz=ed")``
        :return: a configurator
        """

        def _cfg(cfg: ContainerConfiguration):
            if not params:
                return

            for e in params:
                if "=" in e:
                    k, v = e.split("=", maxsplit=1)
                    cfg.env_vars[k] = v
                else:
                    # there's currently no way in our abstraction to only pass the variable name (as
                    # you can do in docker) so we resolve the value here.
                    cfg.env_vars[e] = os.getenv(e)

        return _cfg

    @staticmethod
    def port_cli_params(params: Iterable[str] = None):
        """
        Configures port variables from additional CLI input through the ``-p`` options.

        :param params: a list of port assignments, e.g.,: ``("4000-5000", "8080:80")``
        :return: a configurator
        """

        def _cfg(cfg: ContainerConfiguration):
            if not params:
                return

            for port_mapping in params:
                port_split = port_mapping.split(":")
                protocol = "tcp"
                if len(port_split) == 1:
                    host_port = container_port = port_split[0]
                elif len(port_split) == 2:
                    host_port, container_port = port_split
                elif len(port_split) == 3:
                    _, host_port, container_port = port_split
                else:
                    raise ValueError(f"Invalid port string provided: {port_mapping}")

                host_port_split = host_port.split("-")
                if len(host_port_split) == 2:
                    host_port = [int(host_port_split[0]), int(host_port_split[1])]
                elif len(host_port_split) == 1:
                    host_port = int(host_port)
                else:
                    raise ValueError(f"Invalid port string provided: {port_mapping}")

                if "/" in container_port:
                    container_port, protocol = container_port.split("/")

                container_port_split = container_port.split("-")
                if len(container_port_split) == 2:
                    container_port = [int(container_port_split[0]), int(container_port_split[1])]
                elif len(container_port_split) == 1:
                    container_port = int(container_port)
                else:
                    raise ValueError(f"Invalid port string provided: {port_mapping}")

                cfg.ports.add(host_port, container_port, protocol)

        return _cfg

    @staticmethod
    def volume_cli_params(params: Iterable[str] = None):
        """
        Configures volumes from additional CLI input through the ``-v`` options.

        :param params: a list of volume declarations, e.g.,: ``("./bar:/foo/bar",)``
        :return: a configurator
        """

        def _cfg(cfg: ContainerConfiguration):
            for param in params:
                cfg.volumes.append(VolumeBind.parse(param))

        return _cfg


def get_gateway_port(container: Container) -> int:
    """
    Heuristically determines for the given container the port the gateway will be reachable from the host.
    Parses the container's ``GATEWAY_LISTEN`` if necessary and finds the appropriate port mapping.

    :param container: the localstack container
    :return: the gateway port reachable from the host
    """
    candidates: List[int]

    gateway_listen = container.config.env_vars.get("GATEWAY_LISTEN")
    if gateway_listen:
        candidates = [
            HostAndPort.parse(
                value,
                default_host=constants.LOCALHOST_HOSTNAME,
                default_port=constants.DEFAULT_PORT_EDGE,
            ).port
            for value in gateway_listen.split(",")
        ]
    else:
        candidates = [constants.DEFAULT_PORT_EDGE]

    exposed = container.config.ports.to_dict()

    for candidate in candidates:
        port = exposed.get(f"{candidate}/tcp")
        if port:
            return port

    raise ValueError("no gateway port mapping found")


def get_gateway_url(
    container: Container,
    hostname: str = constants.LOCALHOST_HOSTNAME,
    protocol: str = "http",
) -> str:
    """
    Returns the localstack container's gateway URL reachable from the host. In most cases this will be
    ``http://localhost.localstack.cloud:4566``.

    :param container: the container
    :param hostname: the hostname to use (default localhost.localstack.cloud)
    :param protocol: the URI scheme (default http)
    :return: a URL
    `"""
    return f"{protocol}://{hostname}:{get_gateway_port(container)}"


class Container:
    def __init__(
        self, container_config: ContainerConfiguration, docker_client: ContainerClient | None = None
    ):
        self.config = container_config
        # marker to access the running container
        self.running_container: RunningContainer | None = None
        self.container_client = docker_client or DOCKER_CLIENT

    def configure(self, configurators: ContainerConfigurator | Iterable[ContainerConfigurator]):
        """
        Apply the given configurators to the config of this container.

        :param configurators:
        :return:
        """
        try:
            iterator = iter(configurators)
        except TypeError:
            configurators(self.config)
            return

        for configurator in iterator:
            configurator(self.config)

    def start(self, attach: bool = False) -> RunningContainer:
        # FIXME: this is pretty awkward, but additional_flags in the LocalstackContainer API was
        #  always a list of ["-e FOO=BAR", ...], whereas in the DockerClient it is expected to be
        #  a string. so we need to re-assemble it here. the better way would be to not use
        #  additional_flags here all together. it is still used in ext in
        #  `configure_pro_container` which could be refactored to use the additional port bindings.
        cfg = copy.deepcopy(self.config)
        if not cfg.additional_flags:
            cfg.additional_flags = ""

        # TODO: there could be a --network flag in `additional_flags`. we solve a similar problem
        #  for the ports using `extract_port_flags`. maybe it would be better to consolidate all
        #  this into the ContainerConfig object, like ContainerConfig.update_from_flags(str).
        self._ensure_container_network(cfg.network)

        try:
            id = self.container_client.create_container_from_config(cfg)
        except ContainerException as e:
            if LOG.isEnabledFor(logging.DEBUG):
                LOG.exception("Error while creating container")
            else:
                LOG.error(
                    "Error while creating container: %s\n%s", e.message, to_str(e.stderr or "?")
                )
            raise

        try:
            self.container_client.start_container(id, attach=attach)
        except ContainerException as e:
            LOG.error(
                "Error while starting LocalStack container: %s\n%s",
                e.message,
                to_str(e.stderr),
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise

        self.running_container = RunningContainer(id, container_config=self.config)
        return self.running_container

    def _ensure_container_network(self, network: str | None = None):
        """Makes sure the configured container network exists"""
        if network:
            if network in ["host", "bridge"]:
                return
            try:
                self.container_client.inspect_network(network)
            except NoSuchNetwork:
                LOG.debug("Container network %s not found, creating it", network)
                self.container_client.create_network(network)


class RunningContainer:
    """
    Represents a LocalStack container that is running.
    """

    def __init__(
        self,
        id: str,
        container_config: ContainerConfiguration,
        docker_client: ContainerClient | None = None,
    ):
        self.id = id
        self.config = container_config
        self.container_client = docker_client or DOCKER_CLIENT
        self.name = self.container_client.get_container_name(self.id)
        self._shutdown = False
        self._mutex = threading.Lock()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.shutdown()

    def ip_address(self, docker_network: str | None = None) -> str:
        """
        Get the IP address of the container

        Optionally specify the docker network
        """
        if docker_network is None:
            return self.container_client.get_container_ip(container_name_or_id=self.id)
        else:
            return self.container_client.get_container_ipv4_for_network(
                container_name_or_id=self.id, container_network=docker_network
            )

    def is_running(self) -> bool:
        try:
            self.container_client.inspect_container(self.id)
            return True
        except NoSuchContainer:
            return False

    def get_logs(self) -> str:
        return self.container_client.get_container_logs(self.id, safe=True)

    def stream_logs(self) -> CancellableStream:
        return self.container_client.stream_container_logs(self.id)

    def wait_until_ready(self, timeout: float = None) -> bool:
        return poll_condition(self.is_running, timeout)

    def shutdown(self, timeout: int = 10, remove: bool = True):
        with self._mutex:
            if self._shutdown:
                return
            self._shutdown = True

        try:
            self.container_client.stop_container(container_name=self.id, timeout=timeout)
        except NoSuchContainer:
            pass

        if remove:
            try:
                self.container_client.remove_container(
                    container_name=self.id, force=True, check_existence=False
                )
            except ContainerException as e:
                if "is already in progress" in str(e):
                    return
                raise

    def inspect(self) -> Dict[str, Union[Dict, str]]:
        return self.container_client.inspect_container(container_name_or_id=self.id)

    def attach(self):
        self.container_client.attach_to_container(container_name_or_id=self.id)

    def exec_in_container(self, *args, **kwargs):
        return self.container_client.exec_in_container(
            container_name_or_id=self.id, *args, **kwargs
        )

    def stopped(self) -> Container:
        """
        Convert this running instance to a stopped instance ready to be restarted
        """
        return Container(container_config=self.config, docker_client=self.container_client)


class ContainerLogPrinter:
    """
    Waits on a container to start and then uses ``stream_logs`` to print each line of the logs.
    """

    def __init__(self, container: Container, callback: Callable[[str], None] = print):
        self.container = container
        self.callback = callback

        self._closed = threading.Event()
        self._stream: Optional[CancellableStream] = None

    def _can_start_streaming(self):
        if self._closed.is_set():
            raise IOError("Already stopped")
        if not self.container.running_container:
            return False
        return self.container.running_container.is_running()

    def run(self):
        try:
            poll_condition(self._can_start_streaming)
        except IOError:
            return
        self._stream = self.container.running_container.stream_logs()
        for line in self._stream:
            self.callback(line.rstrip(b"\r\n").decode("utf-8"))

    def close(self):
        self._closed.set()
        if self._stream:
            self._stream.close()


class LocalstackContainerServer(Server):
    container: Container | RunningContainer

    def __init__(
        self, container_configuration: ContainerConfiguration | Container | None = None
    ) -> None:
        super().__init__(config.GATEWAY_LISTEN[0].port, config.GATEWAY_LISTEN[0].host)

        if container_configuration is None:
            port_configuration = PortMappings(bind_host=config.GATEWAY_LISTEN[0].host)
            for addr in config.GATEWAY_LISTEN:
                port_configuration.add(addr.port)

            container_configuration = ContainerConfiguration(
                image_name=get_docker_image_to_start(),
                name=config.MAIN_CONTAINER_NAME,
                volumes=VolumeMappings(),
                remove=True,
                ports=port_configuration,
                entrypoint=os.environ.get("ENTRYPOINT"),
                command=shlex.split(os.environ.get("CMD", "")) or None,
                env_vars={},
            )

        if isinstance(container_configuration, Container):
            self.container = container_configuration
        else:
            self.container = Container(container_configuration)

    def is_up(self) -> bool:
        """
        Checks whether the container is running, and the Ready marker has been printed to the logs.
        """
        if not self.is_container_running():
            return False

        logs = self.container.get_logs()

        if constants.READY_MARKER_OUTPUT not in logs.splitlines():
            return False

        # also checks the edge port health status
        return super().is_up()

    def is_container_running(self) -> bool:
        # if we have not started the container then we are not up
        if not isinstance(self.container, RunningContainer):
            return False

        return self.container.is_running()

    def wait_is_container_running(self, timeout=None) -> bool:
        return poll_condition(self.is_container_running, timeout)

    def start(self) -> bool:
        if isinstance(self.container, RunningContainer):
            raise RuntimeError("cannot start container as container reference has been started")

        return super().start()

    def do_run(self):
        if self.is_container_running():
            raise ContainerExists(
                'LocalStack container named "%s" is already running' % self.container.name
            )

        config.dirs.mkdirs()
        if not isinstance(self.container, Container):
            raise ValueError(f"Invalid container type: {type(self.container)}")

        LOG.debug("starting LocalStack container")
        self.container = self.container.start(attach=False)
        if isinstance(DOCKER_CLIENT, CmdDockerClient):
            DOCKER_CLIENT.default_run_outfile = get_container_default_logfile_location(
                self.container.config.name
            )

        # block the current thread
        self.container.attach()
        return self.container

    def shutdown(self):
        if not isinstance(self.container, RunningContainer):
            raise ValueError(f"Container {self.container} not started")

        return super().shutdown()

    def do_shutdown(self):
        try:
            self.container.shutdown(timeout=10)
            self.container = self.container.stopped()
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


def configure_container(container: Container):
    """
    Configuration routine for the LocalstackContainer.
    """
    port_configuration = PortMappings(bind_host=config.GATEWAY_LISTEN[0].host)

    # base configuration
    container.config.image_name = get_docker_image_to_start()
    container.config.name = config.MAIN_CONTAINER_NAME
    container.config.volumes = VolumeMappings()
    container.config.remove = True
    container.config.ports = port_configuration
    container.config.entrypoint = os.environ.get("ENTRYPOINT")
    container.config.command = shlex.split(os.environ.get("CMD", "")) or None
    container.config.env_vars = {}

    # parse `DOCKER_FLAGS` and add them appropriately
    user_flags = config.DOCKER_FLAGS
    user_flags = extract_port_flags(user_flags, container.config.ports)
    if container.config.additional_flags is None:
        container.config.additional_flags = user_flags
    else:
        container.config.additional_flags = f"{container.config.additional_flags} {user_flags}"

    # get additional parameters from plugins
    hooks.configure_localstack_container.run(container)

    if config.DEVELOP:
        container.config.ports.add(config.DEVELOP_PORT)

    container.configure(
        [
            # external service port range
            ContainerConfigurators.service_port_range,
            ContainerConfigurators.mount_localstack_volume(config.VOLUME_DIR),
            ContainerConfigurators.mount_docker_socket,
            ContainerConfigurators.publish_dns_ports,
            # overwrites any env vars set in the config that were previously set by configurators
            ContainerConfigurators.config_env_vars,
            # ensure that GATEWAY_LISTEN is taken from the config and not
            # overridden by the `config_env_vars` configurator
            # (when not specified in the environment).
            ContainerConfigurators.gateway_listen(config.GATEWAY_LISTEN),
        ]
    )


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
    container_config = ContainerConfiguration(get_docker_image_to_start())
    container = Container(container_config)
    ensure_container_image(console, container)

    configure_container(container)
    container.configure(ContainerConfigurators.cli_params(cli_params or {}))

    status = console.status("Starting LocalStack container")
    status.start()

    # printing the container log is the current way we're occupying the terminal
    def _init_log_printer(line):
        """Prints the console rule separator on the first line, then re-configures the callback
        to print."""
        status.stop()
        console.rule("LocalStack Runtime Log (press [bold][yellow]CTRL-C[/yellow][/bold] to quit)")
        print(line)
        log_printer.callback = print

    log_printer = ContainerLogPrinter(container, callback=_init_log_printer)

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

    shutdown_event = threading.Event()
    shutdown_event_lock = threading.RLock()
    signal.signal(signal.SIGINT, shutdown_handler)

    # start the Localstack container as a Server
    server = LocalstackContainerServer(container)
    log_printer_thread = threading.Thread(
        target=log_printer.run, name="container-log-printer", daemon=True
    )
    try:
        server.start()
        log_printer_thread.start()
        server.join()
        error = server.get_error()
        if error:
            # if the server failed, raise the error
            raise error
    except KeyboardInterrupt:
        print("ok, bye!")
        shutdown_handler()
    finally:
        log_printer.close()


def ensure_container_image(console, container: Container):
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
    container_config = ContainerConfiguration(get_docker_image_to_start())
    container = Container(container_config)
    ensure_container_image(console, container)
    configure_container(container)
    container.configure(ContainerConfigurators.cli_params(cli_params or {}))

    container_config.detach = True

    # start the Localstack container as a Server
    console.log("starting container")
    server = LocalstackContainerServer(container_config)
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
