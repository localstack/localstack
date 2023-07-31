import pytest
import requests
from requests.exceptions import ConnectionError

from localstack.utils.container_utils.container_client import NoSuchNetwork
from localstack.utils.docker_utils import DOCKER_CLIENT
from localstack.utils.net import get_free_tcp_port
from localstack.utils.strings import short_uid
from tests.bootstrap.conftest import ContainerFactory


def test_defaults(container_factory: ContainerFactory):
    """
    The default configuration is to listen on 0.0.0.0:4566
    """
    port = get_free_tcp_port()
    container = container_factory()
    container.config.ports.add(port, 4566)
    container.run(attach=False)
    container.wait_until_ready()

    r = requests.get(f"http://127.0.0.1:{port}/_localstack/health")
    assert r.status_code == 200


def test_gateway_listen_single_value(container_factory: ContainerFactory, cleanups):
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
    container.run(attach=False)
    container.wait_until_ready()

    # check the ports listening on 0.0.0.0
    r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
    assert r.status_code == 200


@pytest.mark.skip(reason="TODO")
def test_gateway_listen_multiple_values(container_factory: ContainerFactory, cleanups):
    """
    Test multiple container ports
    """
    port1 = get_free_tcp_port()
    port2 = get_free_tcp_port()

    network_name = f"net-{short_uid()}"
    try:
        DOCKER_CLIENT.inspect_network(network_name)
    except NoSuchNetwork:
        DOCKER_CLIENT.create_network(network_name)
        cleanups.append(lambda: DOCKER_CLIENT.delete_network(network_name))

    container = container_factory(
        env_vars={
            "GATEWAY_LISTEN": ",".join(
                [
                    "0.0.0.0:5000",
                    "127.0.0.1:2000",
                ]
            )
        },
        network=network_name,
    )
    container.config.ports.add(port1, 5000)
    container.config.ports.add(port2, 2000)
    container.run(attach=False)
    container.wait_until_ready()

    # check the ports listening on 0.0.0.0
    r = requests.get(f"http://127.0.0.1:{port1}/_localstack/health")
    assert r.status_code == 200

    # port2 should not be accessible from the host
    with pytest.raises(ConnectionError):
        requests.get(f"http://127.0.0.1:{port2}/_localstack/health")

    # but should be available on localhost
    stdout, stderr = container.exec_in_container(
        command=["curl", "http://127.0.0.1:2000/_localstack/health"]
    )
    assert stdout == b"Foobar"
