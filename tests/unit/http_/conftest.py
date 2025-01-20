import asyncio
import logging
from asyncio import AbstractEventLoop

import pytest
from hypercorn import Config
from hypercorn.typing import ASGIFramework
from werkzeug.datastructures import Headers
from werkzeug.wrappers import Request as WerkzeugRequest

from localstack.http import Response
from localstack.http.asgi import ASGIAdapter, ASGILifespanListener, WebSocketListener
from localstack.http.hypercorn import HypercornServer
from localstack.utils import net
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture()
def serve_asgi_app():
    _servers = []

    def _create(
        app: ASGIFramework, config: Config = None, event_loop: AbstractEventLoop = None
    ) -> HypercornServer:
        if not config:
            config = Config()
            config.h11_pass_raw_headers = True
            config.bind = f"localhost:{net.get_free_tcp_port()}"

        srv = HypercornServer(app, config, loop=event_loop)
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


@pytest.fixture()
def serve_asgi_adapter(serve_asgi_app):
    def _create(
        wsgi_app,
        lifespan_listener: ASGILifespanListener = None,
        websocket_listener: WebSocketListener = None,
    ):
        loop = asyncio.new_event_loop()
        return serve_asgi_app(
            ASGIAdapter(
                wsgi_app,
                event_loop=loop,
                lifespan_listener=lifespan_listener,
                websocket_listener=websocket_listener,
            ),
            event_loop=loop,
        )

    yield _create


@pytest.fixture()
def httpserver_echo_request_metadata():
    def httpserver_handler(request: WerkzeugRequest) -> Response:
        """
        Simple request handler that returns the incoming request metadata (method, path, url, headers).

        :param request: the incoming HTTP request
        :return: an HTTP response
        """
        response = Response()
        response.set_json(
            {
                "method": request.method,
                "path": request.path,
                "url": request.url,
                "headers": dict(Headers(request.headers)),
            }
        )
        return response

    return httpserver_handler
