import functools
import logging
import platform
import random
from typing import List, Optional, Union

from localstack import config
from localstack.constants import DEFAULT_VOLUME_DIR, DOCKER_IMAGE_NAME
from localstack.utils.collections import ensure_list
from localstack.utils.container_utils.container_client import (
    ContainerClient,
    PortMappings,
    VolumeInfo,
)
from localstack.utils.net import IntOrPort, Port, PortNotAvailableException, PortRange
from localstack.utils.objects import singleton_factory
from localstack.utils.strings import to_str

LOG = logging.getLogger(__name__)


# port range instance used to reserve Docker container ports
PORT_START = 0
PORT_END = 65536
RANDOM_PORT_START = 1024
RANDOM_PORT_END = 65536


def is_docker_sdk_installed() -> bool:
    try:
        import docker  # noqa: F401

        return True
    except ModuleNotFoundError:
        return False


def create_docker_client() -> ContainerClient:
    # never use the sdk client if it is not installed or not in docker - too risky for wrong version
    if config.LEGACY_DOCKER_CLIENT or not is_docker_sdk_installed() or not config.is_in_docker:
        from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient

        LOG.debug(
            "Using CmdDockerClient. LEGACY_DOCKER_CLIENT: %s, SDK installed: %s",
            config.LEGACY_DOCKER_CLIENT,
            is_docker_sdk_installed(),
        )

        return CmdDockerClient()
    else:
        from localstack.utils.container_utils.docker_sdk_client import SdkDockerClient

        LOG.debug(
            "Using SdkDockerClient. LEGACY_DOCKER_CLIENT: %s, SDK installed: %s",
            config.LEGACY_DOCKER_CLIENT,
            is_docker_sdk_installed(),
        )

        return SdkDockerClient()


def get_current_container_id() -> str:
    """
    Returns the ID of the current container, or raises a ValueError if we're not in docker.

    :return: the ID of the current container
    """
    if not config.is_in_docker:
        raise ValueError("not in docker")

    container_id = platform.node()
    if not container_id:
        raise OSError("no hostname returned to use as container id")

    return container_id


def inspect_current_container_mounts() -> List[VolumeInfo]:
    return DOCKER_CLIENT.inspect_container_volumes(get_current_container_id())


@functools.lru_cache()
def get_default_volume_dir_mount() -> Optional[VolumeInfo]:
    """
    Returns the volume information of LocalStack's DEFAULT_VOLUME_DIR (/var/lib/localstack), if mounted,
    else it returns None. If we're not currently in docker a VauleError is raised. in a container, a ValueError is
    raised.

    :return: the volume info of the default volume dir or None
    """
    for volume in inspect_current_container_mounts():
        if volume.destination.rstrip("/") == DEFAULT_VOLUME_DIR:
            return volume

    return None


def get_host_path_for_path_in_docker(path):
    """
    Returns the calculated host location for a given subpath of DEFAULT_VOLUME_DIR inside the localstack container.
    The path **has** to be a subdirectory of DEFAULT_VOLUME_DIR (the dir itself *will not* work).

    :param path: Path to be replaced (subpath of DEFAULT_VOLUME_DIR)
    :return: Path on the host
    """
    if config.is_in_docker:
        volume = get_default_volume_dir_mount()

        if volume:
            if volume.type != "bind":
                raise ValueError(
                    f"Mount to {DEFAULT_VOLUME_DIR} needs to be a bind mount for mounting to work"
                )

            if not path.startswith(f"{DEFAULT_VOLUME_DIR}/") and path != DEFAULT_VOLUME_DIR:
                # We should be able to replace something here.
                # if this warning is printed, the usage of this function is probably wrong.
                # Please check if the target path is indeed prefixed by /var/lib/localstack
                # if this happens, mounts may fail
                LOG.warning(
                    "Error while performing automatic host path replacement for path '%s' to source '%s'",
                    path,
                    volume.source,
                )
            else:
                relative_path = path.removeprefix(DEFAULT_VOLUME_DIR)
                result = volume.source + relative_path
                return result
        else:
            raise ValueError(f"No volume mounted to {DEFAULT_VOLUME_DIR}")

    return path


def container_ports_can_be_bound(ports: Union[IntOrPort, List[IntOrPort]]) -> bool:
    """Determine whether a given list of ports can be bound by Docker containers

    :param ports: single port or list of ports to check
    :return: True iff all ports can be bound
    """
    port_mappings = PortMappings()
    ports = ensure_list(ports)
    for port in ports:
        port = Port.wrap(port)
        port_mappings.add(port.port, port.port, protocol=port.protocol)
    try:
        result = DOCKER_CLIENT.run_container(
            _get_ports_check_docker_image(),
            entrypoint="sh",
            command=["-c", "echo test123"],
            ports=port_mappings,
            remove=True,
        )
    except Exception as e:
        if "port is already allocated" not in str(e):
            LOG.warning(
                "Unexpected error when attempting to determine container port status: %s", e
            )
        return False
    if to_str(result[0]).strip() != "test123":
        LOG.warning(
            "Unexpected output when attempting to determine container port status: %s", result[0]
        )
    return True


class _DockerPortRange(PortRange):
    """
    PortRange which checks whether the port can be bound on the host instead of inside the container.
    """

    def _try_reserve_port(self, port: IntOrPort, duration: int) -> int:
        """Checks if the given port is currently not reserved."""
        port = Port.wrap(port)
        if not self.is_port_reserved(port) and container_ports_can_be_bound(port):
            # reserve the port for a short period of time
            self._ports_cache[port] = "__reserved__"
            if duration:
                self._ports_cache.set_expiry(port, duration)
            return port.port
        else:
            raise PortNotAvailableException(f"The given port ({port}) is already reserved.")


reserved_docker_ports = _DockerPortRange(PORT_START, PORT_END)


def is_port_available_for_containers(port: IntOrPort) -> bool:
    """Check whether the given port can be bound by containers and is not currently reserved"""
    return not is_container_port_reserved(port) and container_ports_can_be_bound(port)


def reserve_container_port(port: IntOrPort, duration: int = None):
    """Reserve the given container port for a short period of time"""
    reserved_docker_ports.reserve_port(port, duration=duration)


def is_container_port_reserved(port: IntOrPort) -> bool:
    """Return whether the given container port is currently reserved"""
    port = Port.wrap(port)
    return reserved_docker_ports.is_port_reserved(port)


def reserve_available_container_port(
    duration: int = None, port_start: int = None, port_end: int = None, protocol: str = None
) -> int:
    """Determine and reserve a port that can then be bound by a Docker container"""

    protocol = protocol or "tcp"

    def _random_port():
        port = None
        while not port or reserved_docker_ports.is_port_reserved(port):
            port_number = random.randint(
                RANDOM_PORT_START if port_start is None else port_start,
                RANDOM_PORT_END if port_end is None else port_end,
            )
            port = Port(port=port_number, protocol=protocol)
        return port

    retries = 10
    for i in range(retries):
        port = _random_port()
        try:
            reserve_container_port(port, duration=duration)
            return port.port
        except PortNotAvailableException as e:
            LOG.debug("Could not bind port %s, trying the next one: %s", port, e)

    raise PortNotAvailableException(
        f"Unable to determine available Docker container port after {retries} retries"
    )


@singleton_factory
def _get_ports_check_docker_image() -> str:
    """
    Determine the Docker image to use for Docker port availability checks.
    Uses either PORTS_CHECK_DOCKER_IMAGE (if configured), or otherwise inspects the running container's image.
    """
    if config.PORTS_CHECK_DOCKER_IMAGE:
        # explicit configuration takes precedence
        return config.PORTS_CHECK_DOCKER_IMAGE
    if not config.is_in_docker:
        # use default image for host mode
        return DOCKER_IMAGE_NAME
    try:
        # inspect the running container to determine the image
        container = DOCKER_CLIENT.inspect_container(get_current_container_id())
        return container["Config"]["Image"]
    except Exception:
        # fall back to using the default Docker image
        return DOCKER_IMAGE_NAME


DOCKER_CLIENT: ContainerClient = create_docker_client()
