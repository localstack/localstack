import socket

import pytest as pytest

from localstack.constants import LOCALHOST
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.net import Port, get_free_udp_port, port_can_be_bound, resolve_hostname


@markers.skip_offline
def test_resolve_hostname():
    assert "127." in resolve_hostname(LOCALHOST)
    assert resolve_hostname("example.com")
    assert resolve_hostname(f"non-existing-host-{short_uid()}") is None


@pytest.mark.parametrize("protocol", ["tcp", "udp"])
def test_port_open(protocol):

    if protocol == "tcp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # bind socket
    sock.bind(("", 0))
    addr, port = sock.getsockname()

    # assert that port cannot be bound
    port = Port(port, protocol=protocol)
    assert not port_can_be_bound(port)

    # close socket, assert that port can be bound
    sock.close()
    assert port_can_be_bound(port)


def test_get_free_udp_port():
    port = get_free_udp_port()
    assert port_can_be_bound(Port(port, "udp"))
