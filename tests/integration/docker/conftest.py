import pytest

from localstack.config import is_env_true
from localstack.utils.docker import CmdDockerClient


def _check_skip():
    if not is_env_true('RUN_DOCKER_TESTS'):
        pytest.skip("RUN_DOCKER_TESTS not set")

    if not CmdDockerClient().has_docker():
        pytest.skip("Docker is not available")


@pytest.fixture
def docker_client():
    _check_skip()  # this is a hack to get a global skip for all tests that require the docker client
    client = CmdDockerClient()
    yield client
