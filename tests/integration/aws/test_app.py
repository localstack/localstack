import json
import threading

import httpx
import pytest
import requests
import websocket
from werkzeug import Request, Response
from werkzeug.exceptions import Forbidden

from localstack import config
from localstack.http import route
from localstack.http.websocket import WebSocketRequest
from localstack.services.edge import ROUTER


class TestExceptionHandlers:
    def test_internal_failure_handler_http_errors(self):
        response = requests.delete(config.internal_service_url() + "/_localstack/health")
        assert response.status_code == 405
        assert response.json() == {
            "error": "Method Not Allowed",
            "message": "The method is not allowed for the requested URL.",
        }
        assert "Allow" in response.headers

    @pytest.mark.skip(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_http_errors(self, cleanups):
        def _raise_error(_request):
            raise Forbidden()

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(config.internal_service_url() + "/_raise_error")
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

        response = requests.patch(config.internal_service_url() + "/_raise_error")
        assert response.status_code == 403
        assert response.json() == {
            "error": "Forbidden",
            "message": "You don't have the permission to access the requested resource. It is "
            "either read-protected or not readable by the server.",
        }

    @pytest.mark.skip(
        reason="fails until the service request parser stops detecting custom route requests as s3 requests"
    )
    def test_router_handler_get_unexpected_errors(self, cleanups):
        def _raise_error(_request):
            raise ValueError("oh noes (this is expected)")

        rule = ROUTER.add("/_raise_error", _raise_error)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(config.internal_service_url() + "/_raise_error")
        assert response.status_code == 500
        assert response.json() == {
            "error": "Unexpected exception",
            "message": "oh noes (this is expected)",
            "type": "ValueError",
        }

    def test_404_unfortunately_detected_as_s3_request(self):
        # FIXME: this is because unknown routes have to be interpreted as s3 requests
        response = requests.get(config.internal_service_url() + "/_raise_error")
        assert response.status_code == 404
        assert "<Error><Code>NoSuchBucket</Code>" in response.text


class TestWerkzeugIntegration:
    def test_response_close_handlers_called_with_router(self, cleanups):
        closed = threading.Event()

        def _test_route(_request):
            r = Response("ok", 200)
            r.call_on_close(closed.set)
            return r

        rule = ROUTER.add("/_test/test_route", _test_route)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(config.internal_service_url() + "/_test/test_route")
        assert response.status_code == 200, response.text
        assert response.text == "ok"

        assert closed.wait(timeout=3), "expected closed.set to be called"

    def test_chunked_response_streaming(self, cleanups):
        chunks = [bytes(f"{n:2}", "utf-8") for n in range(0, 100)]

        def chunk_generator():
            for chunk in chunks:
                yield chunk

        def stream_response_handler(_request) -> Response:
            return Response(response=chunk_generator())

        rule = ROUTER.add("/_test/test_chunked_response", stream_response_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        with requests.get(
            config.internal_service_url() + "/_test/test_chunked_response", stream=True
        ) as r:
            r.raise_for_status()
            chunk_iterator = r.iter_content(chunk_size=None)
            for i, chunk in enumerate(chunk_iterator):
                assert chunk == chunks[i]

    def test_chunked_request_streaming(self, cleanups):
        chunks = [bytes(f"{n:2}", "utf-8") for n in range(0, 100)]

        def handler(request: Request) -> Response:
            data = request.get_data(parse_form_data=False)
            return Response(response=data)

        rule = ROUTER.add("/_test/test_chunked_request", handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        def chunk_generator():
            for chunk in chunks:
                yield chunk

        response = requests.post(
            config.internal_service_url() + "/_test/test_chunked_request", data=chunk_generator()
        )
        assert response.content == b"".join(chunks)

    def test_raw_header_handling(self, cleanups):
        def handler(request: Request) -> Response:
            response = Response()
            response.data = json.dumps({"headers": dict(request.headers)})
            response.mimetype = "application/json"
            response.headers["X-fOO_bar"] = "FooBar"
            return response

        rule = ROUTER.add("/_test/test_raw_header_handling", handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        response = requests.get(
            config.internal_service_url() + "/_test/test_raw_header_handling",
            headers={"x-mIxEd-CaSe": "myheader", "X-UPPER__CASE": "uppercase"},
        )
        returned_headers = response.json()["headers"]
        assert "X-UPPER__CASE" in returned_headers
        assert "x-mIxEd-CaSe" in returned_headers
        assert "X-fOO_bar" in dict(response.headers)


class TestHttps:
    def test_default_cert_works(self):
        response = requests.get(
            config.internal_service_url(host="localhost.localstack.cloud", protocol="https")
            + "/_localstack/health",
        )
        assert response.ok


@pytest.mark.skipif(
    condition=config.GATEWAY_SERVER not in ["hypercorn"],
    reason=f"websockets not supported with {config.GATEWAY_SERVER}",
)
class TestWebSocketIntegration:
    """
    Test for the WebSocket/HandlerChain integration.
    """

    def test_websockets_served_through_edge_router(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebSocketRequest, param: str):
            with request.accept() as ws:
                ws.send(f"hello {param}")
                for data in iter(ws):
                    ws.send(f"echo {data}")
                    if data == "exit":
                        return

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = config.internal_service_url(protocol="ws") + "/_ws/world"

        socket = websocket.WebSocket()
        socket.connect(url)
        assert socket.connected
        assert socket.recv() == "hello world"
        socket.send("foobar")
        assert socket.recv() == "echo foobar"
        socket.send("exit")
        assert socket.recv() == "echo exit"

        socket.shutdown()

    def test_return_response(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebSocketRequest, param: str):
            # if the websocket isn't rejected or accepted, we can use the router to return a response
            return Response("oh noes", 501)

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = config.internal_service_url(protocol="ws") + "/_ws/world"

        socket = websocket.WebSocket()
        with pytest.raises(websocket.WebSocketBadStatusException) as e:
            socket.connect(url)

        assert e.value.status_code == 501
        assert e.value.resp_body == b"oh noes"

    def test_websocket_reject_through_edge_router(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebSocketRequest, param: str):
            request.reject(Response("nope", 403))

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = config.internal_service_url(protocol="ws") + "/_ws/world"

        socket = websocket.WebSocket()
        with pytest.raises(websocket.WebSocketBadStatusException) as e:
            socket.connect(url)

        assert e.value.status_code == 403
        assert e.value.resp_body == b"nope"

    def test_ssl_websockets(self, cleanups):
        @route("/_ws/<param>", methods=["WEBSOCKET"])
        def _echo_websocket_handler(request: WebSocketRequest, param: str):
            with request.accept() as ws:
                ws.send(f"hello {param}")

        rule = ROUTER.add(_echo_websocket_handler)
        cleanups.append(lambda: ROUTER.remove(rule))

        url = (
            config.internal_service_url(host="localhost.localstack.cloud", protocol="wss")
            + "/_ws/world"
        )
        socket = websocket.WebSocket()
        socket.connect(url)
        assert socket.connected
        assert socket.recv() == "hello world"


class TestHTTP2Support:
    @pytest.fixture(autouse=True)
    def _fix_proxy(self, monkeypatch):
        # on linux it also includes [::1], somehow leading to weird URL parsing issues in httpx
        monkeypatch.setenv("no_proxy", "localhost.localstack.cloud,localhost,127.0.0.1")

    def test_http2_http(self):
        host = config.internal_service_url(host="localhost.localstack.cloud", protocol="http")
        with httpx.Client(http1=False, http2=True) as client:
            assert client.get(f"{host}/_localstack/health").status_code == 200

    def test_http2_https(self):
        host = config.internal_service_url(host="localhost.localstack.cloud", protocol="https")
        with httpx.Client(http1=False, http2=True) as client:
            assert client.get(f"{host}/_localstack/health").status_code == 200

    def test_http2_https_localhost(self):
        host = config.internal_service_url(host="localhost", protocol="https")
        with httpx.Client(http1=False, http2=True, verify=False) as client:
            assert client.get(f"{host}/_localstack/health").status_code == 200
