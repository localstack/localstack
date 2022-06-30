import asyncio
import logging
from asyncio import AbstractEventLoop

import pytest
from hypercorn import Config
from hypercorn.typing import ASGI3Framework

from localstack.http.asgi import ASGIAdapter
from localstack.http.hypercorn import HypercornServer
from localstack.utils import net
from localstack.utils.sync import poll_condition

LOG = logging.getLogger(__name__)


@pytest.fixture()
def serve_asgi_app():
    _servers = []

    def _create(
        app: ASGI3Framework, config: Config = None, event_loop: AbstractEventLoop = None
    ) -> HypercornServer:
        if not config:
            config = Config()
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
    def _create(wsgi_app):
        loop = asyncio.new_event_loop()
        return serve_asgi_app(
            ASGIAdapter(
                wsgi_app,
                event_loop=loop,
            ),
            event_loop=loop,
        )

    yield _create
