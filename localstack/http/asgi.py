"""This module contains code to make ASGI play nice with WSGI."""
import asyncio
import io
import logging
import math
import typing as t
from asyncio import AbstractEventLoop
from concurrent.futures import Executor
from io import BufferedReader, RawIOBase
from urllib.parse import quote, unquote, urlparse

if t.TYPE_CHECKING:
    from _typeshed import WSGIApplication, WSGIEnvironment
    from hypercorn.typing import (
        ASGIReceiveCallable,
        ASGISendCallable,
        HTTPScope,
        Scope,
        WebsocketAcceptEvent,
        WebsocketCloseEvent,
        WebsocketConnectEvent,
        WebsocketDisconnectEvent,
        WebsocketReceiveEvent,
        WebsocketResponseBodyEvent,
        WebsocketResponseStartEvent,
        WebsocketScope,
        WebsocketSendEvent,
    )

    _WebsocketResponse = t.Union[
        WebsocketAcceptEvent,
        WebsocketSendEvent,
        WebsocketResponseStartEvent,
        WebsocketResponseBodyEvent,
        WebsocketCloseEvent,
    ]

    _WebsocketRequest = t.Union[
        WebsocketConnectEvent,
        WebsocketReceiveEvent,
        WebsocketDisconnectEvent,
    ]

LOG = logging.getLogger(__name__)

WebSocketEnvironment: t.TypeAlias = t.Dict[str, t.Any]
"""Special WSGIEnvironment that has an `asgi.websocket` key that stores a `Websocket` instance."""


def populate_wsgi_environment(
    environ: t.Union["WSGIEnvironment", WebSocketEnvironment],
    scope: t.Union["HTTPScope", "WebsocketScope"],
):
    """
    Adds the non-IO parts (e.g., excluding wsgi.input) from the ASGI HTTPScope to the WSGI Environment. See
    WSGI Compatibility for more information on why this works:
    https://asgi.readthedocs.io/en/latest/specs/www.html#wsgi-compatibility

    :param environ: the WSGI environment to populate
    :param scope: the ASGI scope as source
    """
    environ["REQUEST_METHOD"] = scope.get("method", "GET")
    # path/uri info
    # prepare the paths for the "WSGI decoding dance" done by werkzeug
    environ["SCRIPT_NAME"] = unquote(quote(scope.get("root_path", "").rstrip("/")), "latin-1")

    path = scope["path"]
    path = path if path[0] == "/" else urlparse(path).path
    environ["PATH_INFO"] = unquote(quote(path), "latin-1")

    query_string = scope.get("query_string")
    if query_string:
        raw_uri = scope["raw_path"] + b"?" + query_string
        environ["QUERY_STRING"] = query_string.decode("latin1")
    else:
        raw_uri = scope["raw_path"]
        environ["QUERY_STRING"] = ""

    environ["RAW_URI"] = environ["REQUEST_URI"] = raw_uri.decode("utf-8")

    # server address / host
    server = scope.get("server") or ("localhost", 80)
    environ["SERVER_NAME"] = server[0]
    environ["SERVER_PORT"] = str(server[1]) if server[1] else "80"

    # http version
    environ["SERVER_PROTOCOL"] = "HTTP/" + scope["http_version"]

    # client (remote) address
    client = scope.get("client")
    if client:
        environ["REMOTE_ADDR"] = client[0]
        environ["REMOTE_PORT"] = str(client[1])

    # headers
    for name, value in scope["headers"]:
        key = name.decode("latin1").upper().replace("-", "_")

        if key not in ["CONTENT_TYPE", "CONTENT_LENGTH"]:
            key = f"HTTP_{key}"

        environ[key] = value.decode("latin1")

    # wsgi specific keys
    environ["wsgi.version"] = (1, 0)
    environ["wsgi.url_scheme"] = scope.get("scheme", "http")
    environ["wsgi.errors"] = io.BytesIO()
    environ["wsgi.multithread"] = True
    environ["wsgi.multiprocess"] = False
    environ["wsgi.run_once"] = False

    # asgi.headers: a custom key to allow downstream applications to circumvent WSGI header processing. these headers
    # should preserve the original casing as the client sends them.
    headers = scope.get("headers")
    environ["asgi.headers"] = headers


class _AsyncGeneratorWrapper:
    def __init__(
        self,
        it: t.Iterator,
        loop: t.Optional[AbstractEventLoop] = None,
        executor: t.Optional[Executor] = None,
    ):
        """
        Wraps a given synchronous Iterator as an async generator, where each invocation to ``next(it)``
        will be wrapped in a coroutine execution.

        :param it: the iterator to wrap
        :param loop: the event loop to run the next invocations
        :param executor: the executor to run the synchronous code
        """
        self.it = it
        self.loop = loop or asyncio.get_event_loop()
        self.executor = executor

    def _next_sync(self):
        try:
            return next(self.it)
        except StopIteration:
            raise StopAsyncIteration

    def __aiter__(self):
        return self

    async def __anext__(self):
        val = await self.loop.run_in_executor(self.executor, self._next_sync)
        return val

    async def aclose(self):
        if close := getattr(self.it, "close", None):
            return await self.loop.run_in_executor(self.executor, close)


def create_wsgi_input(
    receive: "ASGIReceiveCallable", event_loop: t.Optional[AbstractEventLoop] = None
) -> t.IO[bytes]:
    """
    Factory for exposing an ASGIReceiveCallable as an IO stream.

    :param receive: the receive callable
    :param event_loop: the event loop used by the event stream adapter
    :return: a new IO stream that wraps the given receive callable.
    """
    return BufferedReader(RawHTTPRequestEventStreamAdapter(receive, event_loop))


class RawHTTPRequestEventStreamAdapter(RawIOBase):
    """
    An adapter to expose an ASGIReceiveCallable coroutine that returns HTTPRequestEvent instances as an IO
    stream for synchronous WSGI/Werkzeug code. The adapter is a Raw IO stream, meaning it does not have
    optimized ``read``, ``readline``, or ``readlines`` methods. Make sure to use a ``BufferedReader`` around
    the stream adapter.
    """

    def __init__(
        self, receive: "ASGIReceiveCallable", event_loop: t.Optional[AbstractEventLoop] = None
    ) -> None:
        super().__init__()
        self.receive = receive
        self.event_loop = event_loop or asyncio.get_event_loop()

        # internal state
        self._more_body = True
        self._buffered_body = None
        self._buffered_body_pos = 0

    def readable(self) -> bool:
        return True

    def readinto(self, buf: bytearray | memoryview) -> int:
        if not self._more_body:
            return 0

        # max bytes we can write into the buffer
        buf_size = len(buf)

        # _buffered_body holds the carry-over of what we didn't read in the last iteration
        if self._buffered_body is None:
            # read from the underlying socket stream
            recv_future = asyncio.run_coroutine_threadsafe(self.receive(), self.event_loop)
            event = recv_future.result()
            # TODO: disconnect events
            more = event.get("more_body", False)

            if not more:
                self._more_body = False
                return 0

            body = self._buffered_body = event["body"]
            pos = self._buffered_body_pos = 0
        else:
            body = self._buffered_body
            pos = self._buffered_body_pos

        remaining = len(body) - pos

        if remaining <= buf_size:
            # the easiest case, where we write the entire remaining event body into the buffer. we may return
            # less than the buffer size allows, but that's ok for raw IO streams.
            buf[:remaining] = body[pos:]
            self._buffered_body = None
            return remaining

        # in this case, we can read at max buf_size from the body into the buffer, and need to save the
        # rest for the next call
        buf[:buf_size] = body[pos : pos + buf_size]
        self._buffered_body_pos = pos + buf_size

        return buf_size


class WsgiStartResponse:
    """
    A wrapper that exposes an async ``ASGISendCallable`` as synchronous a WSGI ``StartResponse`` protocol callable.
    See this stackoverflow post for a good explanation: https://stackoverflow.com/a/16775731/804840.
    """

    def __init__(
        self,
        send: "ASGISendCallable",
        event_loop: AbstractEventLoop = None,
    ):
        self.send = send
        self.event_loop = event_loop or asyncio.get_event_loop()
        self.sent = 0
        self.content_length = math.inf
        self.finalized = False
        self.started = False

    def __call__(
        self, status: str, headers: t.List[t.Tuple[str, str]], exec_info=None
    ) -> t.Callable[[bytes], t.Any]:
        return self.start_response_sync(status, headers, exec_info)

    def start_response_sync(
        self, status: str, headers: t.List[t.Tuple[str, str]], exec_info=None
    ) -> t.Callable[[bytes], t.Any]:
        """
        The WSGI start_response protocol.

        :param status: the HTTP status (e.g., ``200 OK``) to write
        :param headers: the HTTP headers to write
        :param exec_info: ignored
        :return: a callable that lets you write bytes to the response body
        """
        send = self.send
        loop = self.event_loop

        # start sending response
        asyncio.run_coroutine_threadsafe(
            send(
                {
                    "type": "http.response.start",
                    "status": int(status[:3]),
                    "headers": [(h[0].encode("latin1"), h[1].encode("latin1")) for h in headers],
                }
            ),
            loop,
        ).result()

        self.started = True
        # find out content length if set
        self.content_length = math.inf  # unknown content-length
        for k, v in headers:
            if k.lower() == "content-length":
                self.content_length = int(v)
                break

        return self.write_sync

    def write_sync(self, data: bytes) -> None:
        return asyncio.run_coroutine_threadsafe(self.write(data), self.event_loop).result()

    async def write(self, data: bytes) -> None:
        if not self.started:
            raise ValueError("not started the response yet")
        if getattr(self.send.__self__, "closed", None):
            # the connection has been closed from the client side, set finalized=True to avoid sending more responses
            self.finalized = True
            raise BrokenPipeError("Connection closed")
        await self.send({"type": "http.response.body", "body": data, "more_body": True})
        self.sent += len(data)
        if self.sent >= self.content_length:
            await self.close()

    async def close(self):
        if not self.started:
            raise ValueError("not started the response yet")

        if not self.finalized:
            self.finalized = True
            await self.send({"type": "http.response.body", "body": b"", "more_body": False})


class ASGILifespanListener:
    """
    Simple event handler that is attached to the ASGIAdapter and called on ASGI lifespan events. See
    https://asgi.readthedocs.io/en/latest/specs/lifespan.html.
    """

    def on_startup(self):
        pass

    def on_shutdown(self):
        pass


class ASGIWebSocket:
    """
    A wrapper around an ASGI ``WebsocketScope`` and relevant IO objects that can be used to interact with the websocket
    in synchronous code.

    For send and receive event formats, see https://asgi.readthedocs.io/en/latest/specs/www.html#websocket.
    """

    _scope: "WebsocketScope"
    _receive: "ASGIReceiveCallable"
    _send: "ASGISendCallable"

    def __init__(
        self,
        scope: "WebsocketScope",
        receive: "ASGIReceiveCallable",
        send: "ASGISendCallable",
        loop: AbstractEventLoop,
    ):
        self._scope = scope
        self._receive = receive
        self._send = send
        self._loop = loop

    async def send_async(self, event: "_WebsocketResponse"):
        await self._send(event)

    async def receive_async(self) -> "_WebsocketRequest":
        return await self._receive()

    def send(self, event: "_WebsocketResponse", timeout: float = None) -> None:
        """
        Sends an event to the Websocket. Events can be:

        - websocket.accept: https://asgi.readthedocs.io/en/latest/specs/www.html#accept-send-event
        - websocket.send: https://asgi.readthedocs.io/en/latest/specs/www.html#send-send-event
        - websocket.close: https://asgi.readthedocs.io/en/latest/specs/www.html#close-send-event

        :param event: The event to send
        :param timeout: The number of seconds to wait for the result of the async call
        """
        return asyncio.run_coroutine_threadsafe(self.send_async(event), self._loop).result(
            timeout=timeout
        )

    def receive(self, timeout: float = None) -> "_WebsocketRequest":
        """
        Listens on the websocket and returns the next event. Events can be:

        - websocket.connect: https://asgi.readthedocs.io/en/latest/specs/www.html#connect-receive-event
        - websocket.receive: https://asgi.readthedocs.io/en/latest/specs/www.html#receive-receive-event
        - websocket.disconnect: https://asgi.readthedocs.io/en/latest/specs/www.html#disconnect-receive-event-ws

        :param timeout: The number of seconds to wait for the event
        :return: The received event
        """
        return asyncio.run_coroutine_threadsafe(self.receive_async(), self._loop).result(timeout)

    def respond(
        self, status: int, headers: list[tuple[str, str]] = None, body: t.Iterable[bytes] = None
    ):
        self.send(
            {
                "type": "websocket.http.response.start",
                "status": status,
                "headers": [(h[0].encode("latin1"), h[1].encode("latin1")) for h in headers],
            }
        )
        if body:
            for chunk in body:
                self.send(
                    {
                        "type": "websocket.http.response.body",
                        "body": chunk,
                        "more_body": True,
                    }
                )
        self.send(
            {
                "type": "websocket.http.response.body",
                "body": b"",
                "more_body": False,
            }
        )


class WebSocketListener(t.Protocol):
    """
    Similar protocol to a WSGIApplication, only it expects a Websocket instead of a WSGIEnvironment.
    """

    def __call__(self, environ: WebSocketEnvironment):
        """
        Called when a new Websocket connection is established. To initiate the connection, you need to perform the
        connect handshake yourself. First, receive the ``websocket.connect`` event, and then send the
        ``websocket.accept`` event. Here's a minimal example::

            def accept(self, environ: WebsocketEnvironment):
                websocket = environ['asgi.websocket']
                event = websocket.receive()
                if event['type'] == "websocket.connect":
                    websocket.send({
                        "type": "websocket.accept",
                        "subprotocol": None,
                        "headers": [],
                    })
                else:
                    websocket.send({
                        "type": "websocket.close",
                        "code": 1002, # protocol error
                        "reason": None,
                    })
                    return

                while True:
                    event = websocket.receive()
                    if event["type"] == "websocket.disconnect":
                        return
                    print(event)

        :param environ: The new Websocket environment
        """
        raise NotImplementedError


class ASGIAdapter:
    """
    Adapter to expose a WSGIApplication as an ASGI3Application. This allows you to serve synchronous WSGI applications
    through ASGI servers (e.g., Hypercorn).

    IMPORTANT: The ASGIAdapter needs to use the same event loop as the underlying server. If you pass a new event
    loop to the server, you need to also pass it to the ASGIAdapter.

    https://asgi.readthedocs.io/en/latest/specs/main.html
    """

    def __init__(
        self,
        wsgi_app: "WSGIApplication",
        event_loop: AbstractEventLoop = None,
        executor: Executor = None,
        lifespan_listener: ASGILifespanListener = None,
        websocket_listener: WebSocketListener = None,
    ):
        self.wsgi_app = wsgi_app
        self.event_loop = event_loop or asyncio.get_event_loop()
        self.executor = executor
        self.lifespan_listener = lifespan_listener or ASGILifespanListener()
        self.websocket_listener = websocket_listener

    async def __call__(
        self, scope: "Scope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        """
        The ASGI 3 interface. Can only handle HTTP calls.

        :param scope: the connection scope
        :param receive: the receive callable
        :param send: the send callable
        """
        if scope["type"] == "http":
            return await self.handle_http(scope, receive, send)

        if scope["type"] == "lifespan":
            return await self.handle_lifespan(scope, receive, send)

        if scope["type"] == "websocket":
            return await self.handle_websocket(scope, receive, send)

        raise NotImplementedError("Unhandled protocol %s" % scope["type"])

    def to_wsgi_environment(
        self,
        scope: "HTTPScope",
        receive: "ASGIReceiveCallable",
    ) -> "WSGIEnvironment":
        """
        Creates an IO-ready WSGIEnvironment from the given ASGI HTTP call.

        :param scope: the ASGI HTTP Scope
        :param receive: the ASGI callable to receive the HTTP request
        :return: a WSGIEnvironment
        """
        environ: "WSGIEnvironment" = {}
        populate_wsgi_environment(environ, scope)
        # add IO wrappers
        environ["wsgi.input"] = create_wsgi_input(receive, event_loop=self.event_loop)
        # indicate that the stream is EOF terminated per request
        environ["wsgi.input_terminated"] = True
        return environ

    async def handle_http(
        self, scope: "HTTPScope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        env = self.to_wsgi_environment(scope, receive)

        try:
            response = WsgiStartResponse(send, self.event_loop)

            iterable = await self.event_loop.run_in_executor(
                self.executor, self.wsgi_app, env, response
            )
        except Exception as e:
            LOG.error(
                "Error while trying to schedule execution: %s with environment %s",
                e,
                env,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise

        try:
            if iterable:
                # Generators are also Iterators
                if isinstance(iterable, t.Iterator):
                    iterable = _AsyncGeneratorWrapper(iterable)

                if isinstance(iterable, (t.AsyncIterator, t.AsyncIterable)):
                    async for packet in iterable:
                        await response.write(packet)
                else:
                    for packet in iterable:
                        await response.write(packet)
        except ConnectionError as e:
            client_info = "unknown"
            if client := scope.get("client"):
                address, port = client
                client_info = f"{address}:{port}"
            LOG.debug("Error while writing responses: %s (client_info: %s)", e, client_info)
        finally:
            if iterable and hasattr(iterable, "aclose"):
                await iterable.aclose()
            await response.close()

    def to_websocket_environment(
        self,
        scope: "WebsocketScope",
        receive: "ASGIReceiveCallable",
        send: "ASGISendCallable",
    ) -> WebSocketEnvironment:
        """
        Creates an IO-ready pseudo-WSGI environment from the given ASGI Websocket scope.

        :param scope: the websocket scope
        :param receive: receive callable
        :param send: send callable
        :return: a new websocket environment
        """
        environ: WebSocketEnvironment = {}
        populate_wsgi_environment(environ, scope)
        environ["REQUEST_METHOD"] = "WEBSOCKET"
        environ["asgi.websocket"] = ASGIWebSocket(scope, receive, send, self.event_loop)
        return environ

    async def handle_websocket(
        self, scope: "WebsocketScope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        if not self.websocket_listener:
            raise NotImplementedError("No websocket listener attached")

        # populate a pseudo-WSGI environment with "WEBSOCKET" as method
        # this can later be used to construct a sans-IO Werkzeug request
        environ = self.to_websocket_environment(scope, receive, send)

        try:
            await self.event_loop.run_in_executor(self.executor, self.websocket_listener, environ)
        except Exception as e:
            LOG.error(
                "Error while trying to schedule execution: %s with environment %s",
                e,
                environ,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )
            raise

    async def handle_lifespan(
        self, scope: "HTTPScope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self.event_loop.run_in_executor(
                        self.executor, self.lifespan_listener.on_startup
                    )
                    await send({"type": "lifespan.startup.complete"})
                except Exception as e:
                    await send({"type": "lifespan.startup.failed", "message": f"{e}"})

            elif message["type"] == "lifespan.shutdown":
                try:
                    await self.event_loop.run_in_executor(
                        self.executor, self.lifespan_listener.on_shutdown
                    )
                    await send({"type": "lifespan.shutdown.complete"})
                except Exception as e:
                    await send({"type": "lifespan.shutdown.failed", "message": f"{e}"})
                return
            else:
                return
