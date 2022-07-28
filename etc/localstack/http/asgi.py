"""This module contains code to make ASGI play nice with WSGI."""
import asyncio
import io
import logging
import math
import typing as t
from asyncio import AbstractEventLoop
from concurrent.futures import Executor
from tempfile import SpooledTemporaryFile
from urllib.parse import quote, unquote, urlparse

if t.TYPE_CHECKING:
    from _typeshed import WSGIApplication, WSGIEnvironment
    from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, HTTPScope, Scope

LOG = logging.getLogger(__name__)


def populate_wsgi_environment(environ: "WSGIEnvironment", scope: "HTTPScope"):
    """
    Adds the non-IO parts (e.g., excluding wsgi.input) from the ASGI HTTPScope to the WSGI Environment.

    :param environ: the WSGI environment to populate
    :param scope: the ASGI scope as source
    """
    environ["REQUEST_METHOD"] = scope["method"]
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

    # asgi.headers: a custom key to allow downstream applications to circumvent WSGI header processing. we try to map
    # asgi.headers to a List[Tuple[byte, byte]]. in our case the headers typically come from hypercorn which uses
    # h11/h2 as protocol library. in the case of h2, the headers will be simply a List[Tuple[byte, byte]],
    # and in the case of h11, it will be a Headers object that we can extract the list of raw headers from.
    headers = scope.get("headers")
    environ["asgi.headers"] = headers
    if not isinstance(headers, list):
        try:
            # these are h11 headers from which we extract the raw list
            environ["asgi.headers"] = headers.raw_items()
        except AttributeError:
            environ["asgi.headers"] = headers


async def to_async_generator(
    it: t.Iterator,
    loop: t.Optional[AbstractEventLoop] = None,
    executor: t.Optional[Executor] = None,
) -> t.AsyncGenerator:
    """
    Wraps a given synchronous Iterator as an async generator, where each invocation to ``next(it)``
    will be wrapped in a coroutine execution.

    :param it: the iterator to wrap
    :param loop: the event loop to run the next invocations
    :param executor: the executor to run the synchronous code
    :return: an async generator
    """
    loop = loop or asyncio.get_event_loop()
    stop = object()

    def _next_sync():
        try:
            # this call may potentially call blocking IO, which is why we call it in an executor
            return next(it)
        except StopIteration:
            return stop

    while True:
        val = await loop.run_in_executor(executor, _next_sync)
        if val is stop:
            return
        yield val


class HTTPRequestEventStreamAdapter:
    """
    An adapter to expose an ASGIReceiveCallable coroutine that returns HTTPRequestEvent
    instances, as a PEP 3333 InputStream for consumption in synchronous WSGI/Werkzeug code.
    """

    def __init__(
        self, receive: "ASGIReceiveCallable", event_loop: t.Optional[AbstractEventLoop] = None
    ) -> None:
        super().__init__()
        self.receive = receive
        self.event_loop = event_loop or asyncio.get_event_loop()

        self._more_body = True
        self._buffer = bytearray()
        self._buffer_file = SpooledTemporaryFile()

    def _read_into(self, buf: bytearray) -> t.Tuple[int, bool]:
        if not self._more_body:
            return 0, False

        recv_future = asyncio.run_coroutine_threadsafe(self.receive(), self.event_loop)
        event = recv_future.result()
        # TODO: disconnect events
        body = event["body"]
        more = event.get("more_body", False)
        buf.extend(body)
        self._more_body = more
        return len(body), more

    def read(self, size: t.Optional[int] = None) -> bytes:
        """
        Reads up to ``size`` bytes from the object and returns them. As a convenience, if ``size`` is unspecified or
        ``-1``, all bytes until EOF are returned. Like RawIOBase specifies, only one system call is ever made (in
        this case, a call to the ASGI receive callable). Fewer than ``size`` bytes may be returned if the underlying
        call returns fewer than ``size`` bytes.

        :param size: the number of bytes to read
        :return:
        """
        buf = self._buffer

        if not buf and not self._more_body:
            return b""

        if size is None or size == -1:
            while True:
                read, more = self._read_into(buf)
                if not more:
                    break

            arr = bytes(buf)
            buf.clear()
            return arr

        if len(buf) < size:
            self._read_into(buf)

        copy = bytes(buf[:size])
        self._buffer = buf[size:]
        return copy

    def readline(self, size: t.Optional[int] = None) -> bytes:
        buf = self._buffer
        size = size if size is not None else -1

        while True:
            i = buf.find(b"\n")  # FIXME: scans the whole buffer every time

            if i >= 0:
                if 0 < size < i:
                    break  # no '\n' in range
                else:
                    arr = bytes(buf[: (i + 1)])
                    self._buffer = buf[(i + 1) :]
                    return arr

            # ensure the buffer has at least `size` bytes (or all)
            if size > 0:
                if len(buf) >= size:
                    break
            _, more = self._read_into(buf)
            if not more:
                break

        if size > 0:
            arr = bytes(buf[:size])
            self._buffer = buf[size:]
            return arr
        else:
            arr = bytes(buf)
            buf.clear()
            return arr

    def readlines(self, size: t.Optional[int] = None) -> t.List[bytes]:
        if size is None or size < 0:
            return [line for line in self]

        lines = []
        while size > 0:
            try:
                line = self.__next__()
            except StopIteration:
                return lines

            lines.append(line)
            size = size - len(line)

        return lines

    def __next__(self):
        line = self.readline()
        if line == b"" and not self._more_body:
            raise StopIteration()
        return line

    def __iter__(self):
        return self


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
    ):
        self.wsgi_app = wsgi_app
        self.event_loop = event_loop or asyncio.get_event_loop()
        self.executor = executor

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
        environ["wsgi.input"] = HTTPRequestEventStreamAdapter(receive, event_loop=self.event_loop)
        environ[
            "wsgi.input_terminated"
        ] = True  # indicates that the stream is EOF terminated per request
        return environ

    async def handle_http(
        self, scope: "HTTPScope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        env = self.to_wsgi_environment(scope, receive)

        response = WsgiStartResponse(send, self.event_loop)

        iterable = await self.event_loop.run_in_executor(
            self.executor, self.wsgi_app, env, response
        )

        try:
            if iterable:
                # Generators are also Iterators
                if isinstance(iterable, t.Iterator):
                    iterable = to_async_generator(iterable)

                if isinstance(iterable, (t.AsyncIterator, t.AsyncIterable)):
                    async for packet in iterable:
                        await response.write(packet)
                else:
                    for packet in iterable:
                        await response.write(packet)
        finally:
            await response.close()
