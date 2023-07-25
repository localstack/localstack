import pytest
import requests

from localstack import config
from localstack.config import in_docker
from localstack.utils.bootstrap import LocalstackContainer, LocalstackContainerServer
from localstack.utils.container_utils.container_client import ContainerClient
from localstack.utils.docker_utils import create_docker_client
from localstack.utils.strings import short_uid


@pytest.fixture
def localstack_container():
    server = LocalstackContainerServer()
    assert not server.is_up()

    yield server

    server.shutdown()
    server.join(30)
    assert not server.is_up()


@pytest.fixture(scope="session")
def docker_client() -> ContainerClient:
    return create_docker_client()


@pytest.fixture
def create_network(docker_client: ContainerClient):
    networks = []

    def inner(network_name: str):
        docker_client.create_network(network_name)
        networks.append(network_name)

    yield inner

    for network in networks[::-1]:
        docker_client.delete_network(network)


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestLocalstackContainerServer:
    def test_lifecycle(self, localstack_container):
        localstack_container.container.ports.add(config.EDGE_PORT)
        localstack_container.start()
        assert localstack_container.wait_is_up(60)

        response = requests.get("http://localhost:4566/_localstack/health")

        assert response.ok, "expected health check to return OK: %s" % response.text


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestInterNetworkConnectivity:
    # @pytest.mark.skip(reason="WIP")
    def test_user_defined_network_connectivity(
        self,
        docker_client: ContainerClient,
        # order is important: create_network must come before localstack_container
        create_network,
        localstack_container: LocalstackContainerServer,
    ):
        network_name = f"net-{short_uid()}"
        create_network(network_name)

        container_name = f"ls-{short_uid()}"
        localstack_container.container.name = container_name
        localstack_container.container.network = network_name
        localstack_container.container.ports.add(config.EDGE_PORT)
        localstack_container.start()
        assert localstack_container.wait_is_up(60)

        self.run_connectivity_test_from_external_container(
            docker_client, network_name, localstack_container.container
        )

    def run_connectivity_test_from_external_container(
        self, docker_client: ContainerClient, network_name: str, container: LocalstackContainer
    ):
        docker_client.run_container(
            image_name="localstack/localstack",
            entrypoint="bash",
            network=network_name,
            command=["-c", f"curl http://{container.name}:4566/_localstack/health"],
        )
        # no exception means success
