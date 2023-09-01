import pytest

from localstack.config import in_docker
from localstack.constants import LOCALHOST_HOSTNAME

pytestmarks = pytest.mark.skipif(
    condition=in_docker(), reason="cannot run bootstrap tests in docker"
)


def test_default_network(container_factory, wait_for_localstack_ready):
    ls_container = container_factory(env_vars={"DEBUG": "1"})
    ls_container.config.volumes.append(("/var/run/docker.sock", "/var/run/docker.sock"))
    # start localstack container
    with ls_container.start() as running_ls_container:
        wait_for_localstack_ready(running_ls_container)

        container_ip = running_ls_container.ip_address()
        app_container = container_factory(
            image_name="ghcr.io/simonrw/docker-debug:main",
            command=["sleep", "infinity"],
            dns=container_ip,
        )
        # start application container
        with app_container.start() as running_app_container:
            running_app_container.wait_until_ready()
            stdout, stderr = running_app_container.exec_in_container(
                command=["dig", "+short", LOCALHOST_HOSTNAME]
            )
            assert container_ip in stdout.decode().splitlines()


def test_user_defined_network(container_factory, docker_network, wait_for_localstack_ready):
    ls_container = container_factory(env_vars={"DEBUG": "1"}, network=docker_network)
    ls_container.config.volumes.append(("/var/run/docker.sock", "/var/run/docker.sock"))
    # start localstack container
    with ls_container.start() as running_ls_container:
        wait_for_localstack_ready(running_ls_container)

        container_ip = running_ls_container.ip_address(docker_network=docker_network)
        app_container = container_factory(
            image_name="ghcr.io/simonrw/docker-debug:main",
            command=["sleep", "infinity"],
            dns=container_ip,
            network=docker_network,
        )
        # start application container
        with app_container.start() as running_app_container:
            running_app_container.wait_until_ready()
            stdout, stderr = running_app_container.exec_in_container(
                command=["dig", "+short", LOCALHOST_HOSTNAME]
            )
            assert container_ip in stdout.decode().splitlines()
