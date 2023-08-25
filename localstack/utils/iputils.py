"""
IP utils wraps the 'ip' cli command (from iproute2) and creates a pythonic OO interface around
some of its functionality.
"""

import ipaddress
import json
import subprocess as sp
from typing import Any, Generator, TypedDict

from cachetools import TTLCache, cached


def ip_available() -> bool:
    try:
        output = sp.run(["ip"], capture_output=True)
        return "Usage:" in output.stderr.decode("utf8")
    except FileNotFoundError:
        return False


class Route(TypedDict):
    """
    Represents an entry in the routing table.
    """

    dst: str | ipaddress.IPv4Network
    dev: str
    protocol: str
    prefsrc: ipaddress.IPv4Address
    gateway: ipaddress.IPv4Address | None
    metric: int | None
    flags: list[str]


# Cache with 10 second expiry for the outputs of the results of running the IP command
IP_RESULTS_CACHE = TTLCache(maxsize=100, ttl=10)


def get_routes() -> Generator[Route, None, None]:
    """
    Return a generator over the routes.

    :return: a generator over route descriptions
    """
    yield from _run_ip_command("route", "show")


def get_route(name: str) -> Route:
    """
    Get information about a single route.

    :param name: name of the route to get details for
    :return: the route definition
    """
    return _run_ip_command("route", "show", name)[0]


def get_default_route() -> Route:
    """
    Get information about the default route.

    :return: the definition of the default route
    """
    return get_route("default")


def get_default_gateway() -> ipaddress.IPv4Address:
    """
    Get the IPv4 address for the default gateway.

    :return: the IPv4 address for the default gateway
    """
    return ipaddress.IPv4Address(get_default_route()["gateway"])


# Internal command to run `ip --json ...`
@cached(cache=IP_RESULTS_CACHE)
def _run_ip_command(*args) -> Any:
    cmd = ["ip", "--json"] + list(args)

    try:
        result = sp.check_output(cmd)
    except FileNotFoundError:
        raise RuntimeError("could not find ip binary on path")
    return json.loads(result.decode("utf8"))
