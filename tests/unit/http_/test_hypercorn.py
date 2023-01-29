from contextlib import contextmanager

import requests

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.gateway import Gateway
from localstack.http import Response
from localstack.http.hypercorn import GatewayServer, ProxyServer
from localstack.utils.net import get_free_tcp_port
from localstack.utils.serving import Server


@contextmanager
def server_context(server: Server):
    server.start()
    try:
        yield server
    finally:
        server.shutdown()


def test_gateway_server():
    def echo_request_handler(_: HandlerChain, context: RequestContext, response: Response):
        response.set_response(context.request.data)
        response.status_code = 200
        response.headers = context.request.headers

    gateway = Gateway()
    gateway.request_handlers.append(echo_request_handler)
    port = get_free_tcp_port()
    server = GatewayServer(gateway, port, "127.0.0.1", use_ssl=True)
    with server_context(server):
        get_response = requests.get(
            f"https://localhost.localstack.cloud:{port}", data="Let's see if this works..."
        )
        assert get_response.text == "Let's see if this works..."


def test_proxy_server(httpserver):
    httpserver.expect_request("/base-path/relative-path").respond_with_data("Reached Mock Server.")
    port = get_free_tcp_port()
    proxy_server = ProxyServer(
        f"{httpserver.url_for('/base-path')}", port, "127.0.0.1", use_ssl=True
    )
    with server_context(proxy_server):
        # Test that only the base path is added by the proxy
        response = requests.get(
            f"https://localhost.localstack.cloud:{port}/relative-path", data="data"
        )
        assert response.text == "Reached Mock Server."
