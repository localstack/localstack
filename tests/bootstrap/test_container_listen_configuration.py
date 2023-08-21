import pytest
import requests

from localstack.config import in_docker
from localstack.utils.container_utils.container_client import NoSuchNetwork
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.net import get_free_tcp_port
from localstack.utils.strings import short_uid


@pytest.fixture
def ensure_network(cleanups):
    def _ensure_network(name: str):
        try:
            DOCKER_CLIENT.inspect_network(name)
        except NoSuchNetwork:
            DOCKER_CLIENT.create_network(name)
            cleanups.append(lambda: DOCKER_CLIENT.delete_network(name))

    return _ensure_network


@pytest.fixture
def docker_network(ensure_network):
    network_name = f"net-{short_uid()}"
    ensure_network(network_name)
    return network_name


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestContainerConfiguration:
    def test_defaults(self, container_factory):
        """
        The default configuration is to listen on 0.0.0.0:4566
        """
        port = get_free_tcp_port()
        container = container_factory()
        container.config.ports.add(port, 4566)
        with container.start(attach=False) as running_container:
            running_container.wait_until_ready()

            r = requests.get(f"http://127.0.0.1:{port}/_localstack/health")
            assert r.status_code == 200

    def test_gateway_listen_single_value(self, container_factory):
        """
        Test using GATEWAY_LISTEN to change the hypercorn port
        """
        port1 = get_free_tcp_port()

        container = container_factory(
            env_vars={
                "GATEWAY_LISTEN": "0.0.0.0:5000",
            },
        )
        container.config.ports.add(port1, 5000)
        with container.start(attach=False) as running_container:
            running_container.wait_until_ready()

            # check the ports listening on 0.0.0.0
            r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
            assert r.status_code == 200

    def test_gateway_listen_multiple_values(self, container_factory, docker_network):
        """
        Test multiple container ports
        """
        port1 = get_free_tcp_port()
        port2 = get_free_tcp_port()

        container = container_factory(
            env_vars={
                "GATEWAY_LISTEN": ",".join(
                    [
                        "0.0.0.0:5000",
                        "0.0.0.0:2000",
                    ]
                )
            },
            network=docker_network,
        )
        container.config.ports.add(port1, 5000)
        container.config.ports.add(port2, 2000)
        with container.start(attach=False) as running_container:
            running_container.wait_until_ready()

            # check the ports listening on 0.0.0.0
            r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
            assert r.ok

            # port2 should not be accessible from the host
            r = requests.get(f"http://127.0.0.1:{port2}/_localstack/health")
            assert r.ok
