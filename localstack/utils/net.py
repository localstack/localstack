import logging
import random
import re
import socket
import threading
from contextlib import closing
from typing import Any, List, MutableMapping, NamedTuple, Optional, Union
from urllib.parse import urlparse

import dns.resolver
from dnslib import DNSRecord

from localstack import config, constants

from .collections import CustomExpiryTTLCache
from .numbers import is_number
from .objects import singleton_factory
from .sync import retry

LOG = logging.getLogger(__name__)

# regular expression for IPv4 addresses
IP_REGEX = (
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# many linux kernels use 32768-60999, RFC 6335 is 49152-65535, so we use a mix here
DYNAMIC_PORT_RANGE_START = 32768
DYNAMIC_PORT_RANGE_END = 65536

DEFAULT_PORT_RESERVED_SECONDS = 6
"""Default nuber of seconds a port is reserved in a PortRange."""


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


def port_can_be_bound(port: IntOrPort, address: str = "") -> bool:
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
        sock.bind((address, port.port))
        return True
    except OSError:
        # either the port is used or we don't have permission to bind it
        return False
    except Exception:
        LOG.error(f"cannot bind port {port}", exc_info=LOG.isEnabledFor(logging.DEBUG))
        return False


def get_free_udp_port(blocklist: List[int] = None) -> int:
    blocklist = blocklist or []
    for i in range(10):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(("", 0))
        addr, port = udp.getsockname()
        udp.close()
        if port not in blocklist:
            return port
    raise Exception(f"Unable to determine free UDP port with blocklist {blocklist}")


def get_free_tcp_port(blocklist: List[int] = None) -> int:
    """
    Tries to bind a socket to port 0 and returns the port that was assigned by the system. If the port is
    in the given ``blocklist``, or the port is marked as reserved in ``dynamic_port_range``, the procedure
    is repeated for up to 50 times.

    :param blocklist: an optional list of ports that are not allowed as random ports
    :return: a free TCP port
    """
    blocklist = blocklist or []
    for i in range(50):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
        tcp.close()
        if port not in blocklist and not dynamic_port_range.is_port_reserved(port):
            try:
                dynamic_port_range.mark_reserved(port)
            except ValueError:
                # depending on the ephemeral port range of the system, the allocated port may be outside what
                # we defined as dynamic port range
                pass
            return port
    raise Exception(f"Unable to determine free TCP port with blocklist {blocklist}")


def get_free_tcp_port_range(num_ports: int, max_attempts: int = 50) -> "PortRange":
    """
    Attempts to get a contiguous range of free ports from the dynamic port range. For instance,
    ``get_free_tcp_port_range(4)`` may return the following result: ``PortRange(44000:44004)``.

    :param num_ports: the number of ports in the range
    :param max_attempts: the number of times to retry if a contiguous range was not found
    :return: a port range of free TCP ports
    :raises PortNotAvailableException: if max_attempts was reached to re-try
    """
    if num_ports < 2:
        raise ValueError(f"invalid number of ports {num_ports}")

    def _is_port_range_free(_range: PortRange):
        for _port in _range:
            if dynamic_port_range.is_port_reserved(_port) or not port_can_be_bound(_port):
                return False
        return True

    for _ in range(max_attempts):
        # try to find a suitable starting point (leave enough space at the end)
        port_range_start = random.randint(
            dynamic_port_range.start, dynamic_port_range.end - num_ports - 1
        )
        port_range = PortRange(port_range_start, port_range_start + num_ports - 1)

        # check that each port in the range is available (has not been reserved and can be bound)
        # we don't use dynamic_port_range.reserve_port because in case the port range check fails at some port
        # all ports up until then would be reserved
        if not _is_port_range_free(port_range):
            continue

        # port range found! mark them as reserved in the dynamic port range and return
        for port in port_range:
            dynamic_port_range.mark_reserved(port)
        return port_range

    raise PortNotAvailableException("reached max_attempts when trying to find port range")


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
    """Exception which indicates that the PortRange could not reserve a port."""

    pass


class PortRange:
    """Manages a range of ports that can be reserved and requested."""

    def __init__(self, start: int, end: int):
        """
        Create a new port range. The port range is inclusive, meaning ``PortRange(5000,5005)`` is 6 ports
        including both 5000 and 5005. This is different from ``range`` which is not inclusive, i.e.::

            PortRange(5000, 5005).as_range() == range(5000, 5005 + 1)

        :param start: the start port (inclusive)
        :param end: the end of the range (inclusive).
        """
        self.start = start
        self.end = end

        # cache for locally available ports (ports are reserved for a short period of a few seconds)
        self._ports_cache: MutableMapping[Port, Any] = CustomExpiryTTLCache(
            maxsize=len(self),
            ttl=DEFAULT_PORT_RESERVED_SECONDS,
        )
        self._ports_lock = threading.RLock()

    def as_range(self) -> range:
        """
        Returns a ``range(start, end+1)`` object representing this port range.

        :return: a range
        """
        return range(self.start, self.end + 1)

    def reserve_port(self, port: Optional[IntOrPort] = None, duration: Optional[int] = None) -> int:
        """
        Reserves the given port (if it is still free). If the given port is None, it reserves a free port from the
        configured port range for external services. If a port is given, it has to be within the configured
        range of external services (i.e., in the range [self.start, self.end)).

        :param port: explicit port to check or None if a random port from the configured range should be selected
        :param duration: the time in seconds the port is reserved for (defaults to a few seconds)
        :return: reserved, free port number (int)
        :raises PortNotAvailableException: if the given port is outside the configured range, it is already bound or
                    reserved, or if the given port is none and there is no free port in the configured service range.
        """
        ports_range = self.as_range()
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
            f"No free network ports available in {self!r} (currently reserved: %s)",
            list(self._ports_cache.keys()),
        )

    def is_port_reserved(self, port: IntOrPort) -> bool:
        """
        Checks whether the port has been reserved in this PortRange. Does not check whether the port can be
        bound or not, and does not check whether the port is in range.

        :param port: the port to check
        :return: true if the port is reserved within the range
        """
        port = Port.wrap(port)
        return self._ports_cache.get(port) is not None

    def mark_reserved(self, port: IntOrPort, duration: int = None):
        """
        Marks the given port as reserved for the given duration, regardless of whether it is free for not.

        :param port: the port to reserve
        :param duration: the duration
        :raises ValueError: if the port is not in this port range
        """
        port = Port.wrap(port)

        if port.port not in self.as_range():
            raise ValueError(f"port {port} not in {self!r}")

        with self._ports_lock:
            # reserve the port for a short period of time
            self._ports_cache[port] = "__reserved__"
            if duration:
                self._ports_cache.set_expiry(port, duration)

    def _try_reserve_port(self, port: IntOrPort, duration: int) -> int:
        """Checks if the given port is currently not reserved and can be bound."""
        port = Port.wrap(port)

        if self.is_port_reserved(port):
            raise PortNotAvailableException(f"The given port ({port}) is already reserved.")
        if not self._port_can_be_bound(port):
            raise PortNotAvailableException(f"The given port ({port}) is already in use.")

        self.mark_reserved(port, duration)
        return port.port

    def _port_can_be_bound(self, port: IntOrPort) -> bool:
        """
        Internal check whether the port can be bound. Will open a socket connection and see if the port is
        available. Can be overwritten by subclasses to provide a custom implementation.

        :param port: the port to check
        :return: true if the port is free on the system
        """
        return port_can_be_bound(port)

    def __len__(self):
        return self.end - self.start + 1

    def __iter__(self):
        return self.as_range().__iter__()

    def __repr__(self):
        return f"PortRange({self.start}:{self.end})"


@singleton_factory
def get_docker_host_from_container() -> str:
    """
    Get the hostname/IP to connect to the host from within a Docker container (e.g., Lambda function).
    The logic is roughly as follows:
      1. return `host.docker.internal` if we're running in host mode, in a non-Linux OS
      2. return the IP address that `host.docker.internal` (or alternatively `host.containers.internal`)
        resolves to, if we're inside Docker
      3. return the Docker bridge IP (config.DOCKER_BRIDGE_IP) as a fallback, if option (2) fails
    """
    result = config.DOCKER_BRIDGE_IP
    try:
        if not config.is_in_docker and not config.is_in_linux:
            # If we're running outside Docker (in host mode), and would like the Lambda containers to be able
            # to access services running on the local machine, return `host.docker.internal` accordingly
            result = "host.docker.internal"
        if config.is_in_docker:
            try:
                result = socket.gethostbyname("host.docker.internal")
            except socket.error:
                result = socket.gethostbyname("host.containers.internal")
    except socket.error:
        # TODO if neither host resolves, we might be in linux. We could just use the default gateway then
        pass
    return result


def get_addressable_container_host(default_local_hostname: str = None) -> str:
    """
    Return the target host to address endpoints exposed by Docker containers, depending on
    the current execution context.

    If we're currently executing within Docker, then return get_docker_host_from_container(); otherwise, return
    the value of `LOCALHOST_HOSTNAME`, assuming that container endpoints are exposed and accessible under localhost.

    :param default_local_hostname: local hostname to return, if running outside Docker (defaults to LOCALHOST_HOSTNAME)
    """
    default_local_hostname = default_local_hostname or constants.LOCALHOST_HOSTNAME
    return get_docker_host_from_container() if config.is_in_docker else default_local_hostname


def send_dns_query(
    name: str,
    port: int = 53,
    ip_address: str = "127.0.0.1",
    qtype: str = "A",
    timeout: float = 1.0,
    tcp: bool = False,
) -> DNSRecord:
    LOG.debug("querying %s:%d for name %s", ip_address, port, name)
    request = DNSRecord.question(qname=name, qtype=qtype)
    reply_bytes = request.send(dest=ip_address, port=port, tcp=tcp, timeout=timeout, ipv6=False)
    return DNSRecord.parse(reply_bytes)


dynamic_port_range = PortRange(DYNAMIC_PORT_RANGE_START, DYNAMIC_PORT_RANGE_END)
"""The dynamic port range."""
