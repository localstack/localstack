import logging
import re
import socket
import threading
from contextlib import closing
from typing import Any, List, MutableMapping, NamedTuple, Optional, Union
from urllib.parse import urlparse

import dns.resolver

from .collections import CustomExpiryTTLCache
from .numbers import is_number
from .sync import retry

LOG = logging.getLogger(__name__)

# regular expression for IPv4 addresses
IP_REGEX = (
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


class Port(NamedTuple):
    """Represents a network port, with port number and protocol (TCP/UDP)"""

    port: int
    """the port number"""
    protocol: str
    """network protocol name (usually 'tcp' or 'udp')"""

    @classmethod
    def wrap(cls, port: "IntOrPort") -> "Port":
        """Return the given port as a Port object, using 'tcp' as the default protocol."""
        if isinstance(port, Port):
            return port
        return Port(port=port, protocol="tcp")


# simple helper type to encapsulate int/Port argument types
IntOrPort = Union[int, Port]


def is_port_open(
    port_or_url: Union[int, str],
    http_path: str = None,
    expect_success: bool = True,
    protocols: Optional[Union[str, List[str]]] = None,
    quiet: bool = True,
):
    from localstack.utils.http import safe_requests

    protocols = protocols or ["tcp"]
    port = port_or_url
    if is_number(port):
        port = int(port)
    host = "localhost"
    protocol = "http"
    protocols = protocols if isinstance(protocols, list) else [protocols]
    if isinstance(port, str):
        url = urlparse(port_or_url)
        port = url.port
        host = url.hostname
        protocol = url.scheme
    nw_protocols = []
    nw_protocols += [socket.SOCK_STREAM] if "tcp" in protocols else []
    nw_protocols += [socket.SOCK_DGRAM] if "udp" in protocols else []
    for nw_protocol in nw_protocols:
        with closing(
            socket.socket(socket.AF_INET if ":" not in host else socket.AF_INET6, nw_protocol)
        ) as sock:
            sock.settimeout(1)
            if nw_protocol == socket.SOCK_DGRAM:
                try:
                    if port == 53:
                        dnshost = "127.0.0.1" if host == "localhost" else host
                        resolver = dns.resolver.Resolver()
                        resolver.nameservers = [dnshost]
                        resolver.timeout = 1
                        resolver.lifetime = 1
                        answers = resolver.query("google.com", "A")
                        assert len(answers) > 0
                    else:
                        sock.sendto(bytes(), (host, port))
                        sock.recvfrom(1024)
                except Exception:
                    if not quiet:
                        LOG.exception("Error connecting to UDP port %s:%s", host, port)
                    return False
            elif nw_protocol == socket.SOCK_STREAM:
                result = sock.connect_ex((host, port))
                if result != 0:
                    if not quiet:
                        LOG.warning(
                            "Error connecting to TCP port %s:%s (result=%s)", host, port, result
                        )
                    return False
    if "tcp" not in protocols or not http_path:
        return True
    host = f"[{host}]" if ":" in host else host
    url = f"{protocol}://{host}:{port}{http_path}"
    try:
        response = safe_requests.get(url, verify=False)
        return not expect_success or response.status_code < 400
    except Exception:
        return False


def wait_for_port_open(
    port: int, http_path: str = None, expect_success=True, retries=10, sleep_time=0.5
):
    """Ping the given TCP network port until it becomes available (for a given number of retries).
    If 'http_path' is set, make a GET request to this path and assert a non-error response."""
    return wait_for_port_status(
        port,
        http_path=http_path,
        expect_success=expect_success,
        retries=retries,
        sleep_time=sleep_time,
    )


def wait_for_port_closed(
    port: int, http_path: str = None, expect_success=True, retries=10, sleep_time=0.5
):
    return wait_for_port_status(
        port,
        http_path=http_path,
        expect_success=expect_success,
        retries=retries,
        sleep_time=sleep_time,
        expect_closed=True,
    )


def wait_for_port_status(
    port: int,
    http_path: str = None,
    expect_success=True,
    retries=10,
    sleep_time=0.5,
    expect_closed=False,
):
    """Ping the given TCP network port until it becomes (un)available (for a given number of retries)."""

    def check():
        status = is_port_open(port, http_path=http_path, expect_success=expect_success)
        if bool(status) != (not expect_closed):
            raise Exception(
                "Port %s (path: %s) was not %s"
                % (port, http_path, "closed" if expect_closed else "open")
            )

    return retry(check, sleep=sleep_time, retries=retries)


def port_can_be_bound(port: IntOrPort) -> bool:
    """
    Return whether a local port (TCP or UDP) can be bound to. Note that this is a stricter check
    than is_port_open(...) above, as is_port_open() may return False if the port is
    not accessible (i.e., does not respond), yet cannot be bound to.
    """
    try:
        port = Port.wrap(port)
        if port.protocol == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        elif port.protocol == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            LOG.debug("Unsupported network protocol '%s' for port check", port.protocol)
            return False
        sock.bind(("", port.port))
        return True
    except Exception:
        return False


def get_free_tcp_port(blocklist: List[int] = None) -> int:
    blocklist = blocklist or []
    for i in range(10):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        tcp.close()
        if port not in blocklist:
            return port
    raise Exception(f"Unable to determine free TCP port with blocklist {blocklist}")


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve the given hostname and return its IP address, or None if it cannot be resolved."""
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None


def is_ip_address(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False


def is_ipv4_address(address: str) -> bool:
    """
    Checks if passed string looks like an IPv4 address
    :param address: Possible IPv4 address
    :return: True if string looks like IPv4 address, False otherwise
    """
    return bool(re.match(IP_REGEX, address))


class PortNotAvailableException(Exception):
    """Exception which indicates that the PortPool could not reserve a port."""

    pass


class PortRange:
    """Manages a range of ports that can be reserved and requested."""

    def __init__(self, start: int, end: int):
        # cache for locally available ports (ports are reserved for a short period of a few seconds)
        self._ports_cache: MutableMapping[Port, Any] = CustomExpiryTTLCache(maxsize=100, ttl=6)
        self._ports_lock = threading.RLock()
        self.start = start
        self.end = end

    def reserve_port(self, port: Optional[IntOrPort] = None, duration: Optional[int] = None) -> int:
        """
        Reserves the given port (if it is still free). If the given port is None, it reserves a free port from the
        configured port range for external services. If a port is given, it has to be within the configured
        range of external services (i.e., in the range [self.start, self.end)).
        :param port: explicit port to check or None if a random port from the configured range should be selected
        :return: reserved, free port number (int)
        :raises: PortNotAvailableException if the given port is outside the configured range, it is already bound or
                    reserved, or if the given port is none and there is no free port in the configured service range.
        """
        ports_range = range(self.start, self.end)
        port = Port.wrap(port) if port is not None else port
        if port is not None and port.port not in ports_range:
            raise PortNotAvailableException(
                f"The requested port ({port}) is not in the port range ({ports_range})."
            )
        with self._ports_lock:
            if port is not None:
                return self._try_reserve_port(port, duration=duration)
            else:
                for port_in_range in ports_range:
                    try:
                        return self._try_reserve_port(port_in_range, duration=duration)
                    except PortNotAvailableException:
                        # We ignore the fact that this single port is reserved, we just check the next one
                        pass
        raise PortNotAvailableException(
            "No free network ports available in the port range (currently reserved: %s)",
            list(self._ports_cache.keys()),
        )

    def is_port_reserved(self, port: IntOrPort) -> bool:
        port = Port.wrap(port)
        return self._ports_cache.get(port) is not None

    def _try_reserve_port(self, port: IntOrPort, duration: int) -> int:
        """Checks if the given port is currently not reserved and can be bound."""
        port = Port.wrap(port)
        if not self.is_port_reserved(port) and port_can_be_bound(port):
            # reserve the port for a short period of time
            self._ports_cache[port] = "__reserved__"
            if duration:
                self._ports_cache.set_expiry(port, duration)
            return port.port
        else:
            raise PortNotAvailableException(f"The given port ({port}) is already reserved.")
