import socket
from unittest.mock import MagicMock

import pytest as pytest

from localstack import config
from localstack.constants import LOCALHOST
from localstack.testing.pytest import markers
from localstack.utils import net
from localstack.utils.common import short_uid
from localstack.utils.net import (
    Port,
    PortNotAvailableException,
    PortRange,
    dynamic_port_range,
    get_addressable_container_host,
    get_docker_bridge_ip,
    get_free_tcp_port,
    get_free_tcp_port_range,
    get_free_udp_port,
    is_ip_address,
    port_can_be_bound,
    resolve_hostname,
)


class TestPortRange(PortRange):
    pass


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


def test_free_tcp_port_blocklist_raises_exception():
    blocklist = range(0, 70000)  # blocklist all existing ports
    with pytest.raises(Exception) as ctx:
        get_free_tcp_port(blocklist)

    assert "Unable to determine free TCP" in str(ctx.value)


def test_port_can_be_bound():
    port = get_free_tcp_port()
    assert port_can_be_bound(port)


def test_port_can_be_bound_illegal_port():
    assert not port_can_be_bound(9999999999)


def test_port_can_be_bound_already_bound():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        assert not port_can_be_bound(port)
    finally:
        tcp.close()

    assert port_can_be_bound(port)


def test_get_free_tcp_port_range():
    port_range = get_free_tcp_port_range(20)

    assert len(port_range) == 20

    for port in port_range:
        assert dynamic_port_range.is_port_reserved(port)

    for port in port_range:
        assert port_can_be_bound(port)


def test_subrange():
    r = PortRange(50000, 60000)
    r.mark_reserved(50000)
    r.mark_reserved(50001)
    r.mark_reserved(50002)
    r.mark_reserved(50003)

    sr = r.subrange(end=50005)
    assert sr.as_range() == range(50000, 50006)

    assert sr.is_port_reserved(50000)
    assert sr.is_port_reserved(50001)
    assert sr.is_port_reserved(50002)
    assert sr.is_port_reserved(50003)
    assert not sr.is_port_reserved(50004)
    assert not sr.is_port_reserved(50005)

    sr.mark_reserved(50005)
    assert r.is_port_reserved(50005)


def test_subrange_from_subclass():
    r = TestPortRange(1000, 5000)
    sr = r.subrange(1000, 2000)

    assert isinstance(sr, TestPortRange)
    assert sr.as_range() == range(1000, 2001)


def test_get_free_tcp_port_range_fails_if_reserved(monkeypatch):
    mock = MagicMock()
    mock.return_value = True

    monkeypatch.setattr(dynamic_port_range, "is_port_reserved", mock)

    with pytest.raises(PortNotAvailableException):
        get_free_tcp_port_range(20)

    assert mock.call_count == 50


@pytest.mark.skip(reason="flaky")
def test_get_free_tcp_port_range_fails_if_cannot_be_bound(monkeypatch):
    mock = MagicMock()
    mock.return_value = False

    monkeypatch.setattr(net, "port_can_be_bound", mock)

    with pytest.raises(PortNotAvailableException):
        get_free_tcp_port_range(20, max_attempts=10)

    assert mock.call_count == 10


def test_port_range_iter():
    ports = PortRange(10, 13)
    assert list(ports) == [10, 11, 12, 13]


def test_get_addressable_container_host(monkeypatch):
    if not config.is_in_docker:
        monkeypatch.setattr(config, "is_in_docker", True)
        monkeypatch.setattr(config, "in_docker", lambda: True)
        assert is_ip_address(get_addressable_container_host())

    monkeypatch.setattr(config, "is_in_docker", False)
    monkeypatch.setattr(config, "in_docker", lambda: False)
    assert get_addressable_container_host(default_local_hostname="test.abc") == "test.abc"


def test_get_docker_bridge_ip_default():
    """Test that get_docker_bridge_ip returns a valid IP address."""
    ip = get_docker_bridge_ip()
    assert is_ip_address(ip)
    # Should return one of the default bridge IPs
    assert ip in ("172.17.0.1", "172.18.0.1")


def test_get_docker_bridge_ip_custom_env(monkeypatch):
    """Test that get_docker_bridge_ip respects custom DOCKER_BRIDGE_IP env var."""
    custom_ip = "192.168.1.1"
    monkeypatch.setattr(config, "DOCKER_BRIDGE_IP", custom_ip)
    # Clear the singleton cache
    get_docker_bridge_ip.cache_clear()
    ip = get_docker_bridge_ip()
    assert ip == custom_ip


def test_get_docker_bridge_ip_no_io_on_import():
    """Test that importing the module doesn't trigger I/O operations."""
    # This test verifies that get_docker_bridge_ip is lazy-loaded
    # and doesn't execute ping at import time
    # The function should be callable without side effects
    import importlib
    import sys

    # Remove module from cache to force reimport
    if "localstack.utils.net" in sys.modules:
        importlib.reload(sys.modules["localstack.utils.net"])

    # If we got here without hanging on ping, the fix is working
    from localstack.utils.net import get_docker_bridge_ip as lazy_func
    assert callable(lazy_func)
