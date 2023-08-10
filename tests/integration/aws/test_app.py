import pytest
import requests
import websocket
from werkzeug import Response
from werkzeug.exceptions import Forbidden

from localstack.config import get_edge_url
from localstack.http import route
from localstack.http.websocket import WebsocketRequest
from localstack.services.edge import ROUTER


class TestExceptionHandlers:
    def test_internal_failure_handler_http_errors(self):
        response = requests.delete(get_edge_url() + "/_localstack/health")
        assert response.status_code == 405
        assert response.json() == {
            "error": "Method Not Allowed",
            "message": "The method is not allowed for the requested URL.",
        }
        assert "Allow" in response.headers

    @pytest.mark.xfail(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_http_errors(self, cleanups):
        def _raise_error(_request):
            raise Forbidden()

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 403
        assert response.json() == {
            "error": "Forbidden",
            "message": "You don't have the permission to access the requested resource. It is "
            "either read-protected or not readable by the server.",
        }

    def test_router_handler_patch_http_errors(self, cleanups):
        # this one works because PATCH operations are not detected by the service name parser as s3 requests
        def _raise_error(_request):
            raise Forbidden()

        rule = ROUTER.add("/_raise_error", _raise_error, methods=["PATCH"])
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.patch(get_edge_url() + "/_raise_error")
        assert response.status_code == 403
        assert response.json() == {
            "error": "Forbidden",
            "message": "You don't have the permission to access the requested resource. It is "
            "either read-protected or not readable by the server.",
        }

    @pytest.mark.xfail(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_unexpected_errors(self, cleanups):
        def _raise_error(_request):
            raise ValueError("oh noes (this is expected)")

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 500
        assert response.json() == {
            "error": "Unexpected exception",
            "message": "oh noes (this is expected)",
            "type": "ValueError",
        }

    def test_404_unfortunately_detected_as_s3_request(self):
        # FIXME: this is because unknown routes have to be interpreted as s3 requests
        response = requests.get(get_edge_url() + "/_raise_error")
        assert response.status_code == 404
        assert "<Error><Code>NoSuchBucket</Code>" in response.text

    def test_websockets_served_through_edge_router(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebsocketRequest, param: str):
            with request.accept() as ws:
                ws.send(f"hello {param}")
                for data in iter(ws):
                    ws.send(f"echo {data}")
                    if data == "exit":
                        return

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = get_edge_url(protocol="ws") + "/_ws/world"

        socket = websocket.WebSocket()
        socket.connect(url)
        assert socket.connected
        assert socket.recv() == "hello world"
        socket.send("foobar")
        assert socket.recv() == "echo foobar"
        socket.send("exit")
        assert socket.recv() == "echo exit"

        socket.shutdown()

    def test_websocket_reject_through_edge_router(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebsocketRequest, param: str):
            request.reject(Response("nope", 403))

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = get_edge_url(protocol="ws") + "/_ws/world"

        socket = websocket.WebSocket()
        with pytest.raises(websocket.WebSocketBadStatusException) as e:
            socket.connect(url)

            assert e.value.status_code == 403
            assert e.value.resp_body == "nope"
