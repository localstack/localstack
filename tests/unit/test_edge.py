from typing import List

import pytest
import requests
from pytest_httpserver.httpserver import HTTPServer

from localstack.config import HostAndPort
from localstack.services.edge import start_proxy
from localstack.utils.net import get_free_tcp_port


def gateway_listen_value(httpserver: HTTPServer) -> List[HostAndPort]:
    return [HostAndPort(host=httpserver.host, port=httpserver.port)]


def test_edge_tcp_proxy(httpserver):
    # Prepare the target server
    httpserver.expect_request("/").respond_with_data(
        "Target Server Response", status=200, content_type="text/plain"
    )

    # Point the Edge TCP proxy towards the target server
    gateway_listen = gateway_listen_value(httpserver)

    # Start the TCP proxy
    port = get_free_tcp_port()
    proxy_server = start_proxy(
        listen_str=f"127.0.0.1:{port}",
        target_address=gateway_listen[0],
        asynchronous=True,
    )
    proxy_server.wait_is_up()

    # Check that the forwarding works correctly
    try:
        response = requests.get(f"http://localhost:{port}")
        assert response.status_code == 200
        assert response.text == "Target Server Response"
    finally:
        proxy_server.shutdown()


def test_edge_tcp_proxy_does_not_terminate_on_connection_error():
    # Point the Edge TCP proxy towards a port which is not bound to any server
    dst_port = get_free_tcp_port()

    # Start the TCP proxy
    port = get_free_tcp_port()
    proxy_server = start_proxy(
        listen_str=f"127.0.0.1:{port}",
        target_address=HostAndPort(host="127.0.0.1", port=dst_port),
        asynchronous=True,
    )
    try:
        proxy_server.wait_is_up()
        # Start the proxy server and send a request (which is proxied towards a non-bound port)
        with pytest.raises(requests.exceptions.ConnectionError):
            requests.get(f"http://localhost:{port}")

        # Bind an HTTP server to the target port
        httpserver = HTTPServer(host="localhost", port=dst_port, ssl_context=None)
        try:
            httpserver.start()
            httpserver.expect_request("/").respond_with_data(
                "Target Server Response", status=200, content_type="text/plain"
            )
            # Now that the target server is up and running, the proxy request is successful
            response = requests.get(f"http://localhost:{port}")
            assert response.status_code == 200
            assert response.text == "Target Server Response"
        finally:
            httpserver.clear()
            if httpserver.is_running():
                httpserver.stop()
    finally:
        proxy_server.shutdown()
