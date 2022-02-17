import pytest

from localstack.config import is_env_not_false
from localstack.utils.container_utils.docker_cmd_client import CmdDockerClient
from localstack.utils.container_utils.docker_sdk_client import SdkDockerClient
from localstack.utils.docker_utils import DOCKER_CLIENT


def _check_skip():
    if not is_env_not_false("SKIP_DOCKER_TESTS"):
        pytest.skip("SKIP_DOCKER_TESTS is set")

    if not DOCKER_CLIENT.has_docker():
        pytest.skip("Docker is not available")


@pytest.fixture(
    params=[CmdDockerClient(), SdkDockerClient()], ids=["CmdDockerClient", "SdkDockerClient"]
)
def docker_client(request):
    _check_skip()  # this is a hack to get a global skip for all tests that require the docker client
    yield request.param
