import functools
import typing as t

from werkzeug import Response
from werkzeug._internal import _wsgi_decoding_dance
from werkzeug.datastructures import EnvironHeaders, Headers
from werkzeug.sansio.request import Request as _SansIORequest
from werkzeug.wsgi import _get_server

from .asgi import ASGIWebsocket, WebsocketEnvironment, WebsocketListener


class WebsocketDisconnected(IOError):
    default_code = 1005
    """https://asgi.readthedocs.io/en/latest/specs/www.html#disconnect-receive-event-ws"""

    def __init__(self, code: int = None):
        self.code = code if code is not None else self.default_code
        super().__init__(f"Websocket disconnected code={self.code}")


class Websocket:
    request: "WebsocketRequest"
    socket: ASGIWebsocket

    def __init__(self, request: "WebsocketRequest", socket: ASGIWebsocket):
        self.request = request
        self.socket = socket

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __iter__(self):
        while True:
            try:
                yield self.receive()
            except WebsocketDisconnected:
                break

    def send(self, text_or_bytes: str | bytes, timeout: float = None):
        if isinstance(text_or_bytes, str):
            self.socket.send(
                {
                    "type": "websocket.send",
                    "bytes": None,
                    "text": text_or_bytes,
                },
                timeout=timeout,
            )
        else:
            self.socket.send(
                {
                    "type": "websocket.send",
                    "bytes": text_or_bytes,
                    "text": None,
                },
                timeout=timeout,
            )

    def receive(self) -> str:
        event = self.socket.receive()
        if event["type"] == "websocket.receive":
            text = event.get("text")
            if text is not None:
                return text

            buf = event.get("bytes")
            if buf is not None:
                return buf.decode("utf-8")

            raise ValueError("Both bytes and text are None in the websocket.receive event.")
        elif event["type"] == "websocket.disconnect":
            raise WebsocketDisconnected(event.get("code"))
        else:
            raise ValueError(f"Unexpected websocket event type {event['type']}")

    def close(self, code: int = 1000, reason: t.Optional[str] = None, timeout: float = None):
        """
        Sends a ``websocket.close`` event to the Websocket.

        :param code: the websocket close code.
        :param reason: optional reason
        :param timeout: connection timeout
        """
        self.socket.send(
            {
                "type": "websocket.close",
                "code": code,
                "reason": reason,
            },
            timeout=timeout,
        )


class WebsocketRequest(_SansIORequest):
    def __init__(self, environ: WebsocketEnvironment):
        # copied from werkzeug.wrappers.request
        super().__init__(
            method=environ.get("REQUEST_METHOD", "WEBSOCKET"),
            scheme=environ.get("wsgi.url_scheme", "ws"),
            server=_get_server(environ),
            root_path=_wsgi_decoding_dance(environ.get("SCRIPT_NAME") or ""),
            path=_wsgi_decoding_dance(environ.get("PATH_INFO") or ""),
            query_string=environ.get("QUERY_STRING", "").encode("latin1"),
            headers=Headers(EnvironHeaders(environ)),
            remote_addr=environ.get("REMOTE_ADDR"),
        )
        self.environ = environ

        self.shallow = True  # compatibility with werkzeug.Request

        self._upgraded = False
        self._rejected = False
        self._socket: ASGIWebsocket = environ["asgi.websocket"]

    def is_upgraded(self) -> bool:
        return self._upgraded

    def is_rejected(self) -> bool:
        return self._rejected

    def reject(self, response: Response):
        if self._upgraded:
            raise ValueError("Websocket connection already upgraded")
        if self._rejected:
            raise ValueError("Websocket connection already rejected")

        self._socket.respond(
            response.status_code,
            response.headers.to_wsgi_list(),
            response.iter_encoded(),
        )
        self._rejected = True

    def close(self):
        if self._rejected or self._upgraded:
            return

        self._socket.send(
            {
                "type": "websocket.close",
                "code": 1000,
                "reason": None,
            },
        )

    def accept(
        self, subprotocol: str = None, headers: Headers = None, timeout: float = None
    ) -> Websocket:
        """
        Performs the connection handshake: receive the ``websocket.connect`` event from the websocket and
        then send the ``websocket.accept`` event. If the handshake failed because the websocket sent an
        unexpected exception, the connection is closed and the method raises an error.

        :param subprotocol: The subprotocol the server wishes to accept. Optional
        :param headers: Response headers
        :param timeout: connection timeout
        :return: a Websocket
        """
        if self._upgraded:
            raise ValueError("Websocket connection already upgraded")
        if self._rejected:
            raise ValueError("Websocket connection already rejected")

        event = self._socket.receive(timeout)
        if event["type"] == "websocket.connect":
            if headers:
                asgi_headers = [
                    (k.encode("latin1"), v.encode("latin1")) for k, v in headers.items()
                ]
            else:
                asgi_headers = []

            self._socket.send(
                {
                    "type": "websocket.accept",
                    "subprotocol": subprotocol,
                    "headers": asgi_headers,
                },
                timeout=timeout,
            )
            self._upgraded = True
            return Websocket(self, self._socket)

        else:
            self._socket.send(
                {
                    "type": "websocket.close",
                    "code": 1003,
                    "reason": "Expected websocket.connect event",
                },
                timeout,
            )
            raise IOError(f"Unexpected event {event}")

    @classmethod
    def listener(cls, fn: t.Callable[["WebsocketRequest"], None]) -> WebsocketListener:
        from werkzeug.exceptions import HTTPException

        @functools.wraps(fn)
        def application(*args):
            request = cls(args[-1])
            try:
                fn(*args[:-1] + (request,))
            except HTTPException as e:
                resp = e.get_response(args[-1])
                request.reject(resp)
            finally:
                request.close()

        return application
