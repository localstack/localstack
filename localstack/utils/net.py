import logging
import re
import socket
import threading
from contextlib import closing
from typing import List, Optional, Union
from urllib.parse import urlparse

import cachetools
import dns.resolver

from .sync import retry

LOG = logging.getLogger(__name__)

# regular expression for IPv4 addresses
IP_REGEX = (
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_port_open(
    port_or_url: Union[int, str],
    http_path: str = None,
    expect_success: bool = True,
    protocols: Optional[List[str]] = None,
    quiet: bool = True,
):
    from localstack.utils.common import is_number, safe_requests

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
        with closing(socket.socket(socket.AF_INET, nw_protocol)) as sock:
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
    url = "%s://%s:%s%s" % (protocol, host, port, http_path)
    try:
        response = safe_requests.get(url, verify=False)
        return not expect_success or response.status_code < 400
    except Exception:
        return False


def wait_for_port_open(
    port: int, http_path: str = None, expect_success=True, retries=10, sleep_time=0.5
):
    """Ping the given network port until it becomes available (for a given number of retries).
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
    """Ping the given network port until it becomes (un)available (for a given number of retries)."""

    def check():
        status = is_port_open(port, http_path=http_path, expect_success=expect_success)
        if bool(status) != (not expect_closed):
            raise Exception(
                "Port %s (path: %s) was not %s"
                % (port, http_path, "closed" if expect_closed else "open")
            )

    return retry(check, sleep=sleep_time, retries=retries)


def port_can_be_bound(port: int) -> bool:
    """Return whether a local port can be bound to. Note that this is a stricter check
    than is_port_open(...) above, as is_port_open() may return False if the port is
    not accessible (i.e., does not respond), yet cannot be bound to."""
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", port))
        return True
    except Exception:
        return False


def get_free_tcp_port(blacklist: List[int] = None) -> int:
    blacklist = blacklist or []
    for i in range(10):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        tcp.close()
        if port not in blacklist:
            return port
    raise Exception("Unable to determine free TCP port with blacklist %s" % blacklist)


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
        self._PORTS_CACHE = cachetools.TTLCache(maxsize=100, ttl=6)
        self._PORTS_LOCK = threading.RLock()
        self.start = start
        self.end = end

    def reserve_port(self, port: int = None) -> int:
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
        if port is not None and port not in ports_range:
            raise PortNotAvailableException(
                f"The requested port ({port}) is not in the port range ({ports_range})."
            )
        with self._PORTS_LOCK:
            if port is not None:
                return self._check_port(port)
            else:
                for port_in_range in ports_range:
                    try:
                        return self._check_port(port_in_range)
                    except PortNotAvailableException:
                        # We ignore the fact that this single port is reserved, we just check the next one
                        pass
        raise PortNotAvailableException(
            "No free network ports available in the port range (currently reserved: %s)",
            list(self._PORTS_CACHE.keys()),
        )

    def _check_port(self, port: int) -> int:
        """Checks if the given port is currently not reserved and can be bound."""
        if not self._PORTS_CACHE.get(port) and port_can_be_bound(port):
            # reserve the port for a short period of time
            self._PORTS_CACHE[port] = "__reserved__"
            return port
        else:
            raise PortNotAvailableException(f"The given port ({port}) is already reserved.")
