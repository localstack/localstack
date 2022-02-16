import logging

from localstack import config
from localstack.utils.container_utils.container_client import ContainerClient

"""Type alias for a simple version of VolumeBind"""

LOG = logging.getLogger(__name__)


def is_docker_sdk_installed() -> bool:
    try:
        import docker  # noqa: F401

        return True
    except ModuleNotFoundError:
        return False


def create_docker_client() -> ContainerClient:
    if config.LEGACY_DOCKER_CLIENT or not is_docker_sdk_installed():
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


DOCKER_CLIENT: ContainerClient = create_docker_client()
