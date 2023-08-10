import threading

import pytest
import websocket

from localstack.http import Router
from localstack.http.websocket import WebsocketDisconnected, WebsocketRequest


def test_websocket_basic_interaction(serve_asgi_adapter):
    raised = threading.Event()

    @WebsocketRequest.listener
    def app(request: WebsocketRequest):
        with request.accept() as ws:
            ws.send("hello")
            assert ws.receive() == "foobar"
            ws.send("world")

        with pytest.raises(WebsocketDisconnected):
            ws.receive()

        raised.set()

    server = serve_asgi_adapter(wsgi_app=None, websocket_listener=app)

    client = websocket.WebSocket()
    client.connect(server.url.replace("http://", "ws://"))
    assert client.recv() == "hello"
    client.send("foobar")
    assert client.recv() == "world"
    client.close()

    assert raised.wait(timeout=3)


def test_router_integration(serve_asgi_adapter):
    router = Router()

    def _handler(request: WebsocketRequest, request_args: dict):
        with request.accept() as ws:
            ws.send("foo")
            ws.send(f"id={request_args['id']}")

    router.add("/foo/<id>", _handler)

    server = serve_asgi_adapter(
        wsgi_app=None, websocket_listener=WebsocketRequest.listener(router.dispatch)
    )
    client = websocket.WebSocket()
    client.connect(server.url.replace("http://", "ws://") + "/foo/bar")
    assert client.recv() == "foo"
    assert client.recv() == "id=bar"
