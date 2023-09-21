import boto3
import pytest
import requests

from localstack.config import in_docker
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators
from localstack.utils.net import get_free_tcp_port


@pytest.mark.skipif(condition=in_docker(), reason="cannot run bootstrap tests in docker")
class TestContainerConfiguration:
    def test_defaults(self, container_factory: ContainerFactory, wait_for_localstack_ready):
        """
        The default configuration is to listen on 0.0.0.0:4566
        """
        port = get_free_tcp_port()
        container = container_factory()
        container.config.ports.add(port, 4566)
        running_container = container.start(attach=False)
        wait_for_localstack_ready(running_container)

        r = requests.get(f"http://127.0.0.1:{port}/_localstack/health")
        assert r.status_code == 200

    def test_gateway_listen_single_value(
        self,
        container_factory: ContainerFactory,
        wait_for_localstack_ready,
        stream_container_logs,
    ):
        """
        Test using GATEWAY_LISTEN to change the hypercorn port
        """
        port1 = get_free_tcp_port()
        gateway_listen_port = 5000

        container = container_factory(
            configurators=[
                ContainerConfigurators.debug,
                ContainerConfigurators.mount_docker_socket,
                ContainerConfigurators.env_vars(
                    {
                        "GATEWAY_LISTEN": f"0.0.0.0:{gateway_listen_port}",
                    }
                ),
            ],
        )
        container.config.ports.add(port1, gateway_listen_port)
        running_container = container.start(attach=False)
        stream_container_logs(container)
        wait_for_localstack_ready(running_container)

        # check the ports listening on 0.0.0.0
        r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
        assert r.status_code == 200

        # check a service is able to run
        client = boto3.client(
            "s3", endpoint_url=f"http://127.0.0.1:{port1}", region_name="us-east-1"
        )
        client.list_buckets()

        # get the container logs
        logs = running_container.get_logs()
        assert f"checking service health s3:{gateway_listen_port}" in logs

    def test_gateway_listen_multiple_values(
        self, container_factory: ContainerFactory, docker_network, wait_for_localstack_ready
    ):
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
        running_container = container.start(attach=False)
        wait_for_localstack_ready(running_container)

        # check the ports listening on 0.0.0.0
        r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
        assert r.ok

        r = requests.get(f"http://127.0.0.1:{port2}/_localstack/health")
        assert r.ok
