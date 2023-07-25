import pytest
import requests

from localstack import config
from localstack.config import in_docker
from localstack.utils.bootstrap import LocalstackContainerServer


@pytest.fixture
def localstack_server():
    server = LocalstackContainerServer()
    assert not server.is_up()

    yield server

    server.shutdown()
    server.join(30)
    assert not server.is_up()


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalstackContainerServer:
    def test_lifecycle(self, localstack_server):
        localstack_server.container.ports.add(config.EDGE_PORT)
        localstack_server.start()
        assert localstack_server.wait_is_up(60)

        response = requests.get("http://localhost:4566/_localstack/health")

        assert response.ok, "expected health check to return OK: %s" % response.text
