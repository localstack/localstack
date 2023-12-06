from ipaddress import IPv4Address

import pytest

from localstack.utils import iputils

# Only run these tests if `ip` is available on the test host
pytestmark = [
    pytest.mark.skipif(condition=not iputils.ip_available, reason="ip command must be available"),
]


def test_ip_route_show():
    # test that the command runs for now
    for _ in list(iputils.get_routes()):
        pass


def test_default_gateway():
    gateway = iputils.get_default_gateway()

    assert isinstance(gateway, IPv4Address)
