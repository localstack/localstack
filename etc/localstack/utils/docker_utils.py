import functools
import logging
import platform
from typing import List, Optional

from localstack import config
from localstack.constants import DEFAULT_VOLUME_DIR
from localstack.utils.container_utils.container_client import ContainerClient, VolumeInfo

"""Type alias for a simple version of VolumeBind"""

LOG = logging.getLogger(__name__)


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


DOCKER_CLIENT: ContainerClient = create_docker_client()
