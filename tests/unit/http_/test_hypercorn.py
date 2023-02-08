import re
from contextlib import contextmanager

import requests
from werkzeug.datastructures import Headers
from werkzeug.wrappers import Request as WerkzeugRequest

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.gateway import Gateway
from localstack.http import Response
from localstack.http.hypercorn import GatewayServer, ProxyServer
from localstack.utils.net import IP_REGEX, get_free_tcp_port
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
    proxy_server = ProxyServer(httpserver.url_for("/base-path"), port, "127.0.0.1", use_ssl=True)
    with server_context(proxy_server):
        # Test that only the base path is added by the proxy
        response = requests.get(
            f"https://localhost.localstack.cloud:{port}/relative-path", data="data"
        )
        assert response.text == "Reached Mock Server."


def test_proxy_server_properly_handles_headers(httpserver):
    def header_echo_handler(request: WerkzeugRequest) -> Response:
        # The proxy needs to preserve multi-value headers in the request to the backend
        headers = Headers(request.headers)
        assert "Multi-Value-Header" in headers
        assert headers["Multi-Value-Header"] == "Value-1,Value-2"

        # The proxy needs to preserve the Host header (some backend systems use the host header to construct Location URLs)
        assert headers["Host"] == f"localhost.localstack.cloud:{port}"

        # The proxy needs to correctly set the "X-Forwarded-For" header
        # It contains the previous XFF header, as well as the IP of the machine which sent the request to the proxy
        assert len(request.access_route) == 2
        assert request.access_route[0] == "127.0.0.3"
        assert re.match(IP_REGEX, request.access_route[1])

        # return the headers
        return Response(headers=headers)

    httpserver.expect_request("").respond_with_handler(header_echo_handler)
    port = get_free_tcp_port()
    proxy_server = ProxyServer(httpserver.url_for("/"), port, "127.0.0.1", use_ssl=True)

    with server_context(proxy_server):
        response = requests.request(
            "GET",
            f"https://localhost.localstack.cloud:{port}/",
            headers={"Multi-Value-Header": "Value-1,Value-2", "X-Forwarded-For": "127.0.0.3"},
        )

        # The proxy needs to preserve multi-value headers in the response from the backend
        assert "Multi-Value-Header" in response.headers
        assert response.headers["Multi-Value-Header"] == "Value-1,Value-2"


def test_proxy_server_with_chunked_request(httpserver, httpserver_echo_request_metadata):
    chunks = [bytes(f"{n:2}", "utf-8") for n in range(0, 100)]

    def handler(request: WerkzeugRequest) -> Response:
        # TODO Change this assertion to check for each sent chunk (once the proxy supports that).
        #   Currently, the proxy does not support streaming the individual chunks directly to the backend.
        #   Instead, the proxy receives the whole payload from the client and then forwards it
        #   (maybe in chunks of different size) to the backend.
        assert b"".join(chunks) == request.get_data(parse_form_data=False)
        return Response()

    httpserver.expect_request("/").respond_with_handler(handler)
    port = get_free_tcp_port()
    proxy_server = ProxyServer(httpserver.url_for("/"), port, "127.0.0.1", use_ssl=True)

    def chunk_generator():
        for chunk in chunks:
            yield chunk

    with server_context(proxy_server):
        response = requests.get(
            f"https://localhost.localstack.cloud:{port}/", data=chunk_generator()
        )
        assert response


def test_proxy_server_with_streamed_response(httpserver):
    chunks = [bytes(f"{n:2}", "utf-8") for n in range(0, 100)]

    def chunk_generator():
        for chunk in chunks:
            yield chunk

    def stream_response_handler(_: WerkzeugRequest) -> Response:
        return Response(response=chunk_generator())

    httpserver.expect_request("").respond_with_handler(stream_response_handler)
    port = get_free_tcp_port()
    proxy_server = ProxyServer(httpserver.url_for("/"), port, "127.0.0.1", use_ssl=True)

    with server_context(proxy_server):
        with requests.get(f"https://localhost.localstack.cloud:{port}/", stream=True) as r:
            r.raise_for_status()
            chunk_iterator = r.iter_content(chunk_size=None)
            # TODO Change this assertion to check for each chunk (once the proxy supports that).
            #   Currently, the proxy does not support streaming the individual chunks directly to the client.
            #   Instead, the proxy receives the whole payload from the backend and then forwards it
            #   (maybe in chunks of different size) to the client.
            received_chunks = list(chunk_iterator)
            assert b"".join(chunks) == b"".join(received_chunks)
