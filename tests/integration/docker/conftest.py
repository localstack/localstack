import pytest

from localstack.config import is_env_not_false
from localstack.utils.docker import DOCKER_CLIENT


def _check_skip():
    if not is_env_not_false("SKIP_DOCKER_TESTS"):
        pytest.skip("SKIP_DOCKER_TESTS is set")

    if not DOCKER_CLIENT.has_docker():
        pytest.skip("Docker is not available")


@pytest.fixture
def docker_client():
    _check_skip()  # this is a hack to get a global skip for all tests that require the docker client
    client = DOCKER_CLIENT
    yield client
