import pytest
import requests

from localstack.config import in_docker
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.net import get_free_tcp_port

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


class TestContainerConfiguration:
    def test_defaults(
        self, container_factory: ContainerFactory, stream_container_logs, wait_for_localstack_ready
    ):
        """
        The default configuration is to listen on 0.0.0.0:4566
        """
        port = get_free_tcp_port()
        container = container_factory(
            configurators=[
                ContainerConfigurators.debug,
                ContainerConfigurators.mount_docker_socket,
                ContainerConfigurators.port(port, 4566),
            ]
        )
        running_container = container.start(attach=False)
        stream_container_logs(container)
        wait_for_localstack_ready(running_container)

        r = requests.get(f"http://127.0.0.1:{port}/_localstack/health")
        assert r.status_code == 200

    def test_gateway_listen_single_value(
        self, container_factory: ContainerFactory, stream_container_logs, wait_for_localstack_ready
    ):
        """
        Test using GATEWAY_LISTEN to change the hypercorn port
        """
        port1 = get_free_tcp_port()
        container = container_factory(
            configurators=[
                ContainerConfigurators.debug,
                ContainerConfigurators.mount_docker_socket,
                ContainerConfigurators.port(port1, 5000),
                ContainerConfigurators.env_vars(
                    {
                        "GATEWAY_LISTEN": "0.0.0.0:5000",
                    }
                ),
            ]
        )
        running_container = container.start(attach=False)
        stream_container_logs(container)
        wait_for_localstack_ready(running_container)

        # check the ports listening on 0.0.0.0
        r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
        assert r.status_code == 200

    def test_gateway_listen_multiple_values(
        self,
        container_factory: ContainerFactory,
        docker_network,
        stream_container_logs,
        wait_for_localstack_ready,
    ):
        """
        Test multiple container ports
        """
        port1 = get_free_tcp_port()
        port2 = get_free_tcp_port()

        container = container_factory(
            configurators=[
                ContainerConfigurators.debug,
                ContainerConfigurators.mount_docker_socket,
                ContainerConfigurators.network(docker_network),
                ContainerConfigurators.port(port1, 5000),
                ContainerConfigurators.port(port2, 2000),
                ContainerConfigurators.env_vars(
                    {
                        "GATEWAY_LISTEN": ",".join(
                            [
                                "0.0.0.0:5000",
                                "0.0.0.0:2000",
                            ]
                        ),
                    }
                ),
            ]
        )
        running_container = container.start(attach=False)
        stream_container_logs(container)
        wait_for_localstack_ready(running_container)

        # check the ports listening on 0.0.0.0
        r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
        assert r.ok

        r = requests.get(f"http://127.0.0.1:{port2}/_localstack/health")
        assert r.ok
