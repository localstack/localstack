import logging

import pytest

from localstack.config import in_docker
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.testing.pytest.container import ContainerFactory
from localstack.utils.bootstrap import ContainerConfigurators

LOG = logging.getLogger(__name__)

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


def test_default_network(
    container_factory: ContainerFactory,
    stream_container_logs,
    wait_for_localstack_ready,
    dns_query_from_container,
):
    ls_container = container_factory(
        configurators=[
            ContainerConfigurators.debug,
            ContainerConfigurators.mount_docker_socket,
        ]
    )
    running_container = ls_container.start()
    stream_container_logs(ls_container)
    wait_for_localstack_ready(running_container)

    container_ip = running_container.ip_address()
    stdout, _ = dns_query_from_container(name=LOCALHOST_HOSTNAME, ip_address=container_ip)

    assert container_ip in stdout.decode().splitlines()


def test_user_defined_network(
    docker_network,
    container_factory: ContainerFactory,
    stream_container_logs,
    wait_for_localstack_ready,
    dns_query_from_container,
):
    ls_container = container_factory(
        configurators=[
            ContainerConfigurators.debug,
            ContainerConfigurators.mount_docker_socket,
            ContainerConfigurators.network(docker_network),
        ]
    )
    running_ls_container = ls_container.start()
    stream_container_logs(ls_container)
    wait_for_localstack_ready(running_ls_container)

    container_ip = running_ls_container.ip_address(docker_network=docker_network)
    stdout, _ = dns_query_from_container(
        name=LOCALHOST_HOSTNAME, ip_address=container_ip, network=docker_network
    )

    assert container_ip in stdout.decode().splitlines()
