import socket

import pytest as pytest

from localstack.constants import LOCALHOST
from localstack.testing.pytest.marking import Markers
from localstack.utils.common import short_uid
from localstack.utils.net import Port, port_can_be_bound, resolve_hostname


@Markers.skip_offline
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
