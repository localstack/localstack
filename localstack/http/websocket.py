import typing as t

from werkzeug._internal import _wsgi_decoding_dance
from werkzeug.datastructures import EnvironHeaders, Headers
from werkzeug.sansio.request import Request as _Request
from werkzeug.wsgi import _get_server

from .asgi import Websocket


class WebsocketRequest(_Request):
    def __init__(self, websocket: Websocket):
        environ = websocket.environ
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
        self.websocket = websocket

        self.shallow = True  # compatibility with werkzeug.Request

        self._initialized = False

    def handshake(
        self, subprotocol: str = None, headers: Headers = None, timeout: float = None
    ) -> bool:
        """
        Performs the connection handshake: receive the ``websocket.connect`` event from the websocket and then send the
        ``websocket.accept`` event. If the handshake failed because the websocket sent an unexpected exception, the
        connection is closed and the method returns False.

        :param subprotocol: The subprotocol the server wishes to accept. Optional
        :param headers: Response headers
        :param timeout: connection timeout
        :return: True if the handshake was successful, False otherwise
        """
        event = self.websocket.receive(timeout)
        if event["type"] == "websocket.connect":
            self.accept(subprotocol, headers, timeout)
            self._initialized = True
            return True
        else:
            self.websocket.send(
                {
                    "type": "websocket.close",
                    "code": 1003,
                    "reason": "Expected websocket.connect event",
                },
                timeout,
            )
            return False

    def iter_decoded(self) -> t.Iterable[str]:
        if not self._initialized:
            raise ValueError("Websocket not yet initialized, call handshake() first")

        while True:
            event = self.websocket.receive()

            if event["type"] == "websocket.receive":
                text = event.get("text")
                if text is not None:
                    yield text
                    continue

                buf = event.get("bytes")
                if buf is not None:
                    yield buf.decode("utf-8")
                    continue

                raise ValueError("Both bytes and text are None in the websocket.receive event.")
            elif event["type"] == "websocket.disconnect":
                return
            else:
                raise ValueError(f"Unexpected websocket event type {event['type']}")

    def __iter__(self):
        return self.iter_decoded()

    def accept(self, subprotocol: str = None, headers: Headers = None, timeout: float = None):
        """
        Sends a ``websocket.accept`` event to the Websocket. This should be sent to the websocket after the
        ``websocket.connect`` event has been received.

        :param subprotocol: The subprotocol the server wishes to accept. Optional
        :param headers: Response headers
        :param timeout: connection timeout
        :return: None
        """

        if headers:
            asgi_headers = [(k.encode("latin1"), v.encode("latin1")) for k, v in headers.items()]
        else:
            asgi_headers = []

        self.websocket.send(
            {
                "type": "websocket.accept",
                "subprotocol": subprotocol,
                "headers": asgi_headers,
            },
            timeout=timeout,
        )

    def close(self, code: int = 1000, reason: t.Optional[str] = None, timeout: float = None):
        """
        Sends a ``websocket.close`` event to the Websocket.

        :param code: the websocket close code.
        :param reason: optional reason
        :param timeout: connection timeout
        """
        self.websocket.send(
            {
                "type": "websocket.close",
                "code": code,
                "reason": reason,
            },
            timeout=timeout,
        )

    def send(self, text_or_bytes: str | bytes, timeout: float = None):
        if isinstance(text_or_bytes, str):
            self.websocket.send(
                {
                    "type": "websocket.send",
                    "bytes": None,
                    "text": text_or_bytes,
                },
                timeout=timeout,
            )
        else:
            self.websocket.send(
                {
                    "type": "websocket.send",
                    "bytes": text_or_bytes,
                    "text": None,
                },
                timeout=timeout,
            )
