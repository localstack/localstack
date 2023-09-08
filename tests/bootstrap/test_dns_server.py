import logging

import pytest

from localstack.config import in_docker
from localstack.constants import LOCALHOST_HOSTNAME
from localstack.testing.pytest.container import ContainerFactory

LOG = logging.getLogger(__name__)

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


def test_default_network(
    container_factory: ContainerFactory, wait_for_localstack_ready, dns_query_from_container
):
    ls_container = container_factory(env_vars={"DEBUG": "1"})
    ls_container.config.volumes.append(("/var/run/docker.sock", "/var/run/docker.sock"))
    running_container = ls_container.start()
    wait_for_localstack_ready(running_container)

    container_ip = running_container.ip_address()
    stdout, _ = dns_query_from_container(name=LOCALHOST_HOSTNAME, ip_address=container_ip)

    assert container_ip in stdout.decode().splitlines()


def test_user_defined_network(
    docker_network,
    container_factory: ContainerFactory,
    wait_for_localstack_ready,
    dns_query_from_container,
):
    ls_container = container_factory(env_vars={"DEBUG": "1"}, network=docker_network)
    ls_container.config.volumes.append(("/var/run/docker.sock", "/var/run/docker.sock"))
    running_ls_container = ls_container.start()
    wait_for_localstack_ready(running_ls_container)

    container_ip = running_ls_container.ip_address(docker_network=docker_network)
    stdout, _ = dns_query_from_container(
        name=LOCALHOST_HOSTNAME, ip_address=container_ip, network=docker_network
    )

    assert container_ip in stdout.decode().splitlines()
