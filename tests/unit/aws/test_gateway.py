import asyncio

import pytest
import requests
from hypercorn import Config

from localstack.aws.api import RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.gateway import Gateway
from localstack.aws.serving.asgi import AsgiGateway
from localstack.http import Response
from localstack.http.hypercorn import HypercornServer
from localstack.utils import net
from localstack.utils.sync import poll_condition


@pytest.fixture
def serve_gateway_hypercorn():
    _servers = []

    def _create(gateway: Gateway) -> HypercornServer:
        config = Config()
        config.h11_pass_raw_headers = True
        config.bind = f"localhost:{net.get_free_tcp_port()}"
        loop = asyncio.new_event_loop()
        srv = HypercornServer(AsgiGateway(gateway, event_loop=loop), config, loop=loop)
        _servers.append(srv)
        srv.start()
        assert srv.wait_is_up(timeout=10), "gave up waiting for server to start up"
        return srv

    yield _create

    for server in _servers:
        server.shutdown()
        assert poll_condition(
            lambda: not server.is_up(), timeout=10
        ), "gave up waiting for server to shut down"


def test_gateway_served_through_hypercorn_preserves_client_headers(serve_gateway_hypercorn):
    def echo_request_headers(chain: HandlerChain, context: RequestContext, response: Response):
        response.set_json({"headers": [(k, v) for k, v in context.request.headers.items()]})
        chain.stop()

    gateway = Gateway()
    gateway.request_handlers.append(echo_request_headers)

    server = serve_gateway_hypercorn(gateway=gateway)

    response = requests.get(
        server.url,
        headers={
            "x-my-header": "value1",
            "Some-Title-Case-Header": "value2",
            "X-UPPER": "value3",
            "KEEPS__underscores_-": "value4",
        },
    )
    headers = response.json()["headers"]

    assert ["x-my-header", "value1"] in headers
    assert ["Some-Title-Case-Header", "value2"] in headers
    assert ["X-UPPER", "value3"] in headers
    assert ["KEEPS__underscores_-", "value4"] in headers
