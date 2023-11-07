from typing import List

import pytest
import requests
from pytest_httpserver.httpserver import HTTPServer
from werkzeug.datastructures import Headers

from localstack.config import HostAndPort
from localstack.services.edge import get_auth_string, start_proxy
from localstack.utils.net import get_free_tcp_port


def gateway_listen_value(httpserver: HTTPServer) -> List[HostAndPort]:
    return [HostAndPort(host=httpserver.host, port=httpserver.port)]


def test_get_auth_string():
    # Typical Header with Authorization
    headers_with_auth = Headers(
        [
            ("X-Amz-Date", "20210313T160953Z"),
            (
                "Authorization",
                (
                    "AWS4-HMAC-SHA256 Credential="
                    "test/20210313/us-east-1/sqs/aws4_request, "
                    "SignedHeaders=content-type;host;x-amz-date, "
                    "Signature="
                    "3cba88ae6cbb8036126d2ba18ba8ded5"
                    "eea9e5484d70822affce9dad03be5993"
                ),
            ),
        ]
    )

    body_with_auth = (
        b"X-Amz-Algorithm=AWS4-HMAC-SHA256&"
        + b"X-Amz-Credential="
        + b"test%2F20210313%2Fus-east-1%2Fsqs%2Faws4_request&"
        + b"X-Amz-Date=20210313T011059Z&"
        + b"X-Amz-Expires=86400000&"
        + b"X-Amz-SignedHeaders=content-type%3Bhost%3Bx-amz-date&"
        + b"X-Amz-Signature="
        + b"3cba88ae6cbb8036126d2ba18ba8ded5eea9e5484d70822affce9dad03be5993"
    )

    # check getting auth string from header with Authorization header
    assert headers_with_auth.get("authorization") == get_auth_string(
        "POST", "/", headers_with_auth, b""
    )

    # check getting auth string from body with authorization params
    assert headers_with_auth.get("authorization") == get_auth_string(
        "POST", "/", Headers(), body_with_auth
    )


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

    # Check that the forwarding works correctly
    try:
        response = requests.get(f"http://localhost:{port}")
        assert response.status_code == 200
        assert response.text == "Target Server Response"
    finally:
        proxy_server.stop()


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
        proxy_server.stop()
