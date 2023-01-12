import json
import logging

import requests

from localstack import config
from localstack.constants import LOCALHOST_HOSTNAME
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


class TestProxyServer:
    def test_start_and_stop(self, monkeypatch):
        monkeypatch.setattr(config, "FORWARD_EDGE_INMEM", False)
        proxy_port = get_free_tcp_port()
        backend_port = get_free_tcp_port()

        server = start_proxy_for_service(
            "myservice",
            proxy_port,
            backend_port,
            update_listener=None,
            quiet=True,
        )

        assert server

        try:
            assert poll_condition(lambda: is_port_open(proxy_port), timeout=15)
        finally:
            server.stop()
            server.join(timeout=15)

        assert not is_port_open(proxy_port)

    def test_ssl_proxy_server(self):
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
        proxy = start_ssl_proxy(proxy_port, port, asynchronous=True)
        wait_for_port_open(proxy_port)

        # invoke SSL proxy server
        url = f"https://{LOCALHOST_HOSTNAME}:{proxy_port}"
        num_requests = 3
        for i in range(num_requests):
            response = requests.get(url, verify=False)
            assert response.status_code == 200

        # assert backend server has been invoked
        assert len(invocations) == num_requests

        # clean up
        proxy.stop()
        server.stop()

    def test_static_route(self):
        class MyListener(ProxyListener):
            def forward_request(self, method, path, *args, **kwargs):
                return {"method": method, "path": path}

        # start proxy server
        listener = MyListener()
        port = get_free_tcp_port()
        server = start_proxy_server(port, update_listener=listener)
        wait_for_port_open(port)

        # request a /static/... path from the server and assert result
        url = f"http://{LOCALHOST_HOSTNAME}:{port}/static/index.html"
        response = requests.get(url, verify=False)
        assert response.ok
        assert json.loads(to_str(response.content)) == {
            "method": "GET",
            "path": "/static/index.html",
        }

        # clean up
        server.stop()
