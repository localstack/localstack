import gzip
import json
import logging
import unittest

import requests

from localstack import config
from localstack.constants import HEADER_ACCEPT_ENCODING, LOCALHOST_HOSTNAME
from localstack.services.generic_proxy import ProxyListener, start_proxy_server
from localstack.services.infra import start_proxy_for_service
from localstack.utils.common import (
    get_free_tcp_port,
    is_port_open,
    poll_condition,
    to_str,
    wait_for_port_open,
)
from localstack.utils.server.proxy_server import start_ssl_proxy

LOG = logging.getLogger(__name__)


class TestProxyServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cfg_val = config.FORWARD_EDGE_INMEM
        config.FORWARD_EDGE_INMEM = False

    @classmethod
    def tearDownClass(cls) -> None:
        config.FORWARD_EDGE_INMEM = cls.cfg_val

    def test_start_and_stop(self):
        proxy_port = get_free_tcp_port()
        backend_port = get_free_tcp_port()

        server = start_proxy_for_service(
            "myservice",
            proxy_port,
            backend_port,
            update_listener=None,
            quiet=True,
            params={"protocol_version": "HTTP/1.0"},
        )

        self.assertIsNotNone(server)

        try:
            self.assertTrue(
                poll_condition(lambda: is_port_open(proxy_port), timeout=15),
                "gave up waiting for port %d" % proxy_port,
            )
        finally:
            print("stopping proxy server")
            server.stop()

        print("waiting max 15 seconds for server to terminate")
        server.join(timeout=15)

        self.assertFalse(is_port_open(proxy_port))


def test_ssl_proxy_server():
    class MyListener(ProxyListener):
        def forward_request(self, *args, **kwargs):
            invocations.append((args, kwargs))
            return {"foo": "bar"}

    invocations = []

    # start SSL proxy
    listener = MyListener()
    port = get_free_tcp_port()
    server = start_proxy_server(port, update_listener=listener, use_ssl=True)
    wait_for_port_open(port)

    # start SSL proxy
    proxy_port = get_free_tcp_port()
    proxy = start_ssl_proxy(proxy_port, port, asynchronous=True, fix_encoding=True)
    wait_for_port_open(proxy_port)

    # invoke SSL proxy server
    url = f"https://{LOCALHOST_HOSTNAME}:{proxy_port}"
    num_requests = 3
    for i in range(num_requests):
        response = requests.get(url, verify=False)
        assert response.status_code == 200

    # assert backend server has been invoked
    assert len(invocations) == num_requests

    # invoke SSL proxy server with gzip response
    headers = {HEADER_ACCEPT_ENCODING: "gzip"}
    response = requests.get(url, headers=headers, verify=False, stream=True)
    result = response.raw.read()
    assert to_str(gzip.decompress(result)) == json.dumps({"foo": "bar"})

    # clean up
    proxy.stop()
    server.stop()
