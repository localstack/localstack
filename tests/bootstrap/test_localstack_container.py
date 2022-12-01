import pytest
import requests

from localstack import config
from localstack.config import in_docker
from localstack.utils.bootstrap import LocalstackContainerServer


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalstackContainerServer:
    def test_lifecycle(self):

        server = LocalstackContainerServer()
        server.container.ports.add(config.EDGE_PORT)

        assert not server.is_up()
        try:
            server.start()
            assert server.wait_is_up(60)

            response = requests.get("http://localhost:4566/_localstack/health")
            assert response.ok, "expected health check to return OK: %s" % response.text
        finally:
            server.shutdown()

        server.join(30)
        assert not server.is_up()
