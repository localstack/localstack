import json
import threading

import pytest
import websocket
from werkzeug.datastructures import Headers

from localstack.http import Router
from localstack.http.websocket import WebSocketDisconnectedError, WebSocketRequest


def test_websocket_basic_interaction(serve_asgi_adapter):
    raised = threading.Event()

    @WebSocketRequest.listener
    def app(request: WebSocketRequest):
        with request.accept() as ws:
            ws.send("hello")
            assert ws.receive() == "foobar"
            ws.send("world")

        with pytest.raises(WebSocketDisconnectedError):
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


def test_websocket_disconnect_while_iter(serve_asgi_adapter):
    """Makes sure that the ``for line in iter(ws)`` pattern works smoothly when the client disconnects."""
    returned = threading.Event()
    received = []

    @WebSocketRequest.listener
    def app(request: WebSocketRequest):
        with request.accept() as ws:
            for line in iter(ws):
                received.append(line)

        returned.set()

    server = serve_asgi_adapter(wsgi_app=None, websocket_listener=app)

    client = websocket.WebSocket()
    client.connect(server.url.replace("http://", "ws://"))

    client.send("foo")
    client.send("bar")
    client.close()

    assert returned.wait(timeout=3)
    assert received[0] == "foo"
    assert received[1] == "bar"


def test_websocket_headers(serve_asgi_adapter):
    @WebSocketRequest.listener
    def echo_headers(request: WebSocketRequest):
        with request.accept(headers=Headers({"x-foo-bar": "foobar"})) as ws:
            ws.send(json.dumps(dict(request.headers)))

    server = serve_asgi_adapter(wsgi_app=None, websocket_listener=echo_headers)

    client = websocket.WebSocket()
    client.connect(
        server.url.replace("http://", "ws://"), header=["Authorization: Basic let-me-in"]
    )

    assert client.handshake_response.status == 101
    assert client.getheaders()["x-foo-bar"] == "foobar"
    doc = client.recv()
    headers = json.loads(doc)
    assert headers["Connection"] == "Upgrade"
    assert headers["Authorization"] == "Basic let-me-in"


def test_router_integration(serve_asgi_adapter):
    router = Router()

    def _handler(request: WebSocketRequest, request_args: dict):
        with request.accept() as ws:
            ws.send("foo")
            ws.send(f"id={request_args['id']}")

    router.add("/foo/<id>", _handler)

    server = serve_asgi_adapter(
        wsgi_app=None,
        websocket_listener=WebSocketRequest.listener(router.dispatch),
    )
    client = websocket.WebSocket()
    client.connect(server.url.replace("http://", "ws://") + "/foo/bar")
    assert client.recv() == "foo"
    assert client.recv() == "id=bar"
