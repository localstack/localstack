"""
Bindings to serve LocalStack using ``twisted.web``.

TODO: both header retaining and TLS multiplexing are implemented in a pretty hacky way.
TODO: websocket support
"""
import logging
import time
import typing as t
from io import BytesIO
from queue import Queue
from typing import List

from rolo.gateway import Gateway
from rolo.websocket import (
    WebSocketDisconnectedError,
    WebSocketListener,
    WebSocketProtocolError,
    WebSocketRequest,
)
from rolo.websocket import (
    adapter as rolows,
)
from twisted.internet import endpoints, interfaces, reactor, ssl
from twisted.internet.epollreactor import EPollReactor
from twisted.internet.protocol import Protocol
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.protocols.tls import BufferingTLSTransport, TLSMemoryBIOFactory
from twisted.python.components import proxyForInterface
from twisted.python.threadpool import ThreadPool
from twisted.web.http import HTTPChannel, _GenericHTTPChannelProtocol
from twisted.web.resource import IResource
from twisted.web.server import NOT_DONE_YET, Request, Site
from twisted.web.server import Request as TwistedRequest
from twisted.web.wsgi import WSGIResource, _WSGIResponse, _wsgiString
from werkzeug.datastructures import Headers
from wsproto import ConnectionType, WSConnection, events
from zope.interface import implementer

from localstack import config
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.config import HostAndPort
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.utils.patch import patch
from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available
from localstack.utils.threads import start_worker_thread

if t.TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment
    from hypercorn.typing import (
        WebsocketAcceptEvent,
        WebsocketCloseEvent,
        WebsocketConnectEvent,
        WebsocketDisconnectEvent,
        WebsocketReceiveEvent,
        WebsocketResponseBodyEvent,
        WebsocketResponseStartEvent,
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

    reactor: EPollReactor


LOG = logging.getLogger(__name__)


@implementer(IResource)
class WebsocketResourceDecorator(proxyForInterface(IResource)):
    original: WSGIResource
    isLeaf = True

    def __init__(
        self,
        original: WSGIResource,
        websocketListener: WebSocketListener,
    ):
        super().__init__(original)
        self.websocketListener = websocketListener
        self.channel = None

    def render(self, request: Request):
        if upgrade := request.getHeader("upgrade"):
            if upgrade.lower() == "websocket":
                self._processWebsocket(request)
                return NOT_DONE_YET

        return super().render(request)

    def _processWebsocket(self, request: Request):
        self.channel = WebSocketChannel(request)
        if isinstance(request.channel.transport, ProtocolWrapper):
            request.transport.wrappedProtocol = self.channel
        else:
            request.transport.protocol = self.channel

        self.channel.initiateUpgrade()

        environment = self._toWsgiEnvironment(request)
        self.original._threadpool.callInThread(self.websocketListener, environment)

    def _toWsgiEnvironment(self, request: Request) -> dict[str, t.Any]:
        environ = to_websocket_environment(request)
        environ["rolo.websocket"] = TwistedWebSocketAdapter(self.channel)
        return environ


def to_websocket_environment(request: Request) -> dict[str, t.Any]:
    """
    Creates a pseudo WSGI environment to be used for the rolo WebsocketRequest.

    :param request: the twisted webserver request
    :return: a WSGI-like environment for rolo
    """
    if request.prepath:
        scriptName = b"/" + b"/".join(request.prepath)
    else:
        scriptName = b""

    if request.postpath:
        pathInfo = b"/" + b"/".join(request.postpath)
    else:
        pathInfo = b""

    parts = request.uri.split(b"?", 1)
    if len(parts) == 1:
        queryString = b""
    else:
        queryString = parts[1]

    # store raw headers
    headers: list[tuple[bytes, bytes]] = []
    for k, vs in request.requestHeaders.getAllRawHeaders():
        for v in vs:
            headers.append((k, v))

    environ = {
        "REQUEST_METHOD": "WEBSOCKET",
        "REMOTE_ADDR": _wsgiString(request.getClientAddress().host),
        "REMOTE_PORT": _wsgiString(str(request.getClientAddress().port)),
        "SCRIPT_NAME": _wsgiString(scriptName),
        "PATH_INFO": _wsgiString(pathInfo),
        "QUERY_STRING": _wsgiString(queryString),
        "CONTENT_TYPE": _wsgiString(request.getHeader(b"content-type") or ""),
        "CONTENT_LENGTH": _wsgiString(request.getHeader(b"content-length") or ""),
        "SERVER_NAME": _wsgiString(request.getRequestHostname()),
        "SERVER_PORT": _wsgiString(str(request.getHost().port)),
        "SERVER_PROTOCOL": _wsgiString(request.clientproto),
        "REQUEST_URI": request.uri.decode("utf-8"),
        "RAW_URI": request.uri.decode("utf-8"),
        "asgi.headers": headers,
    }

    # WSGI headers
    for name, values in request.requestHeaders.getAllRawHeaders():
        name = "HTTP_" + _wsgiString(name).upper().replace("-", "_")
        environ[name] = ",".join(_wsgiString(v) for v in values).replace("\n", " ")

    environ.update(
        {
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": request.isSecure() and "https" or "http",
            "wsgi.run_once": False,
            "wsgi.multithread": True,
            "wsgi.multiprocess": False,
            "wsgi.errors": BytesIO(),
            "wsgi.input": BytesIO(),
        }
    )

    return environ


class TwistedWebSocketAdapter(rolows.WebSocketAdapter):
    channel: "WebSocketChannel"

    def __init__(self, channel: "WebSocketChannel"):
        self.channel = channel

    def receive(self, timeout: float = None) -> rolows.CreateConnection | rolows.Message:
        event = self.channel.eventQueue.get(timeout=timeout)

        if isinstance(event, events.Request):
            return rolows.CreateConnection()
        if isinstance(event, events.BytesMessage):
            return rolows.BytesMessage(event.data)
        elif isinstance(event, events.TextMessage):
            return rolows.TextMessage(event.data)
        elif isinstance(event, events.CloseConnection):
            raise WebSocketDisconnectedError(event.code)
        else:
            raise WebSocketProtocolError(f"Unexpected event type {event.__class__.__name__}")

    def send(self, event: rolows.Message, timeout: float = None):
        if isinstance(event, rolows.TextMessage):
            self.channel.wsSend(events.TextMessage(event.data))
        elif isinstance(event, rolows.BytesMessage):
            self.channel.wsSend(events.BytesMessage(event.data))
        else:
            raise TypeError(f"Unexpected event type {event.__class__.__name__}")

    def respond(
        self,
        status_code: int,
        headers: Headers = None,
        body: t.Iterable[bytes] = None,
        timeout: float = None,
    ):
        self.channel.wsRespond(status_code, headers, body)

    def accept(
        self,
        subprotocol: str = None,
        extensions: list[str] = None,
        extra_headers: Headers = None,
        timeout: float = None,
    ):
        # TODO: extensions and extra headers
        self.channel.wsSend(events.AcceptConnection(subprotocol, extensions=[], extra_headers=[]))

    def close(self, code: int = 1001, reason: str = None, timeout: float = None):
        if not self.channel.closed:
            self.channel.wsClose(code, reason)


class WebSocketChannel(Protocol):
    eventQueue: Queue[events.Event]

    def __init__(self, request: Request):
        self.request = request
        self.wsproto = WSConnection(ConnectionType.SERVER)
        self.eventQueue = Queue()

    @property
    def closed(self):
        return self.request.finished

    def initiateUpgrade(self):
        headers = [(k, v) for k, vs in self.request.requestHeaders.getAllRawHeaders() for v in vs]
        self.wsproto.initiate_upgrade_connection(headers, self.request.path)

        for event in self.wsproto.events():
            self.eventQueue.put(event)
            if isinstance(event, events.CloseConnection):
                self.close()

    def connectionLost(self, reason):
        self.close()

    def dataReceived(self, data: bytes) -> None:
        self.wsproto.receive_data(data)
        for event in self.wsproto.events():
            if isinstance(event, events.Ping):
                self.wsSend(events.Pong(event.payload))
                continue
            # TODO: filter other evet types that are not expected by WebSocketAdapter
            if isinstance(event, events.CloseConnection):
                self.close()
            self.eventQueue.put_nowait(event)

    def wsSend(self, event: events.Event):
        request = self.request
        if request.finished:
            return
        data = self.wsproto.send(event)
        LOG.debug("sending data to transport %s", data)
        request.transport.write(data)

    def wsRespond(
        self,
        statusCode: int,
        extraHeaders: Headers,
        body: t.Iterator[bytes] | None = None,
    ):
        # we could also use self.wsSend(events.RejectConnection(statusCode, ...)) and write manually to the
        # transport, but instead we re-use twisted's request/response mechanism.

        # TODO: set default twisted headers
        request = self.request

        request.setResponseCode(statusCode)
        for k, v in extraHeaders.to_wsgi_list():
            request.responseHeaders.addRawHeader(k, v)

        if body:
            for b in body:
                request.write(b)

        self.close()

    def wsClose(self, code: int = 1000, reason: t.Optional[str] = None):
        try:
            self.wsSend(events.CloseConnection(code, reason))
        finally:
            self.close()

    def close(self):
        if not self.request.finished:
            self.request.finish()
            # special internal poison pill
            self.eventQueue.put_nowait(events.CloseConnection(None))


def update_environment(environ: "WSGIEnvironment", request: TwistedRequest):
    """
    Update the pre-populated WSGI environment with additional data, needed by rolo, from the webserver
    request object.

    :param environ: the environment to update
    :param request: the webserver request object
    """
    # store raw headers
    headers: list[tuple[bytes, bytes]] = []
    for k, vs in request.requestHeaders.getAllRawHeaders():
        for v in vs:
            headers.append((k, v))
    environ["asgi.headers"] = headers

    # TODO: check if twisted input streams are really properly terminated
    # this is needed for streaming requests
    environ["wsgi.input_terminated"] = True

    # create RAW_URI and REQUEST_URI
    environ["REQUEST_URI"] = request.uri.decode("utf-8")
    environ["RAW_URI"] = request.uri.decode("utf-8")
    # client addr/port
    addr = request.getClientAddress()
    environ["REMOTE_ADDR"] = addr.host
    environ["REMOTE_PORT"] = str(addr.port)


@patch(_WSGIResponse.__init__)
def _init_wsgi_response(init, self, reactor, threadpool, application, request):
    """
    Patch to populate the environment with additional variables we need in LocalStack that the server is
    not setting by default.
    """
    init(self, reactor, threadpool, application, request)
    update_environment(self.environ, request)


@patch(_WSGIResponse.startResponse)
def _start_wsgi_response(startReponse, self, status, headers, excInfo=None):
    result = startReponse(self, status, headers, excInfo)
    # before starting the WSGI response, make sure we store the raw case mappings into the response headers
    for header, _ in self.headers:
        header = header.encode("latin-1")
        self.request.responseHeaders._caseMappings[header.lower()] = header
    return result


class TwistedRequestAdapter(TwistedRequest):
    """
    Custom twisted server Request object to handle header casing.
    """

    rawHeaderList: list[tuple[bytes, bytes]]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # instantiate case mappings, these are used by `getAllRawHeaders` to restore casing
        # by default, they are class attributes, so we would override them globally
        self.requestHeaders._caseMappings = dict(self.requestHeaders._caseMappings)
        self.responseHeaders._caseMappings = dict(self.responseHeaders._caseMappings)


class HeaderPreservingHTTPChannel(HTTPChannel):
    """
    Special HTTPChannel implementation that uses ``Headers._caseMappings`` to retain header casing both for
    request headers (server -> WSGI), and  response headers (WSGI -> client).
    """

    requestFactory = TwistedRequestAdapter

    @staticmethod
    def protocol_factory():
        return _GenericHTTPChannelProtocol(HeaderPreservingHTTPChannel())

    def headerReceived(self, line):
        if not super().headerReceived(line):
            return False

        # remember casing of headers for requests
        header, data = line.split(b":", 1)
        request: TwistedRequestAdapter = self.requests[-1]
        request.requestHeaders._caseMappings[header.lower()] = header
        return True

    def writeHeaders(self, version, code, reason, headers):
        """Alternative implementation that writes the raw headers instead of sanitized versions."""
        responseLine = version + b" " + code + b" " + reason + b"\r\n"
        headerSequence = [responseLine]

        for name, value in headers:
            line = name + b": " + value + b"\r\n"
            headerSequence.append(line)

        headerSequence.append(b"\r\n")
        self.transport.writeSequence(headerSequence)

    def isSecure(self):
        # used to determine the WSGI url scheme (http vs https)
        try:
            # ``self.transport`` will be a ``TLSMultiplexer`` instance in our case
            return self.transport.isSecure()
        except AttributeError:
            return super().isSecure()


class TLSMultiplexer(ProtocolWrapper):
    """
    Custom protocol to multiplex HTTPS and HTTP connections over the same port. This is the equivalent of
    ``DuplexSocket``, but since twisted use its own SSL layer and doesn't use `ssl.SSLSocket``, we need to
    implement the multiplexing behavior in the Twisted layer.

    The basic idea is to defer the ``makeConnection`` call until the first data are received, and then
    re-configure the underlying ``wrappedProtocol`` if needed with a TLS wrapper.
    """

    tlsProtocol = BufferingTLSTransport

    def __init__(
        self,
        factory: "WrappingFactory",
        wrappedProtocol: interfaces.IProtocol,
    ):
        super().__init__(factory, wrappedProtocol)
        self._isInitialized = False
        self._isTLS = None
        self._negotiatedProtocol = None

    def makeConnection(self, transport):
        self.connected = 1
        self.transport = transport
        self.factory.registerProtocol(self)  # this is idempotent
        # we defer the actual makeConnection call to the first invocation of dataReceived

    def dataReceived(self, data: bytes) -> None:
        if self._isInitialized:
            super().dataReceived(data)
            return

        # once the first data have been received, we can check whether it's a TLS handshake, then we need
        # to run the actual makeConnection procedure.
        self._isInitialized = True
        self._isTLS = data[0] == 22  # 0x16 is the marker byte identifying a TLS handshake

        if self._isTLS:
            # wrap protocol again in tls protocol
            self.wrappedProtocol = self.tlsProtocol(self.factory, self.wrappedProtocol)
        else:
            if data.startswith(b"PRI * HTTP/2"):
                # TODO: can we do proper protocol negotiation like in ALPN?
                # in the TLS case, this is determined by the ALPN procedure by OpenSSL.
                self._negotiatedProtocol = b"h2"

        # now that we've set the real wrapped protocol, run the make connection procedure
        super().makeConnection(self.transport)
        super().dataReceived(data)

    @property
    def negotiatedProtocol(self) -> str | None:
        if self._negotiatedProtocol:
            return self._negotiatedProtocol
        return self.wrappedProtocol.negotiatedProtocol


class TLSMultiplexerFactory(TLSMemoryBIOFactory):
    protocol = TLSMultiplexer


def stop_thread_pool(self: ThreadPool, stop, timeout: float = None):
    """
    Patch for a custom shutdown procedure for a ThreadPool that waits a given amount of time for all threads.

    :param self: the pool to shut down
    :param stop: the original function
    :param timeout: the maximum amount of time to wait
    """
    # copied from ThreadPool.stop()
    if self.joined:
        return
    if not timeout:
        stop()
        return

    self.joined = True
    self.started = False
    self._team.quit()

    # our own joining logic with timeout
    remaining = timeout
    total_waited = 0

    for thread in self.threads:
        then = time.time()

        # LOG.info("[shutdown] Joining thread %s", thread)
        thread.join(remaining)

        waited = time.time() - then
        total_waited += waited
        remaining -= waited

        if thread.is_alive():
            LOG.warning(
                "[shutdown] Request thread %s still alive after %.2f seconds",
                thread,
                total_waited,
            )

        if remaining <= 0:
            remaining = 0


class GatewayResource(proxyForInterface(IResource)):
    """
    Compound Resource to serve the Gateway.
    """

    def __init__(self, gateway: Gateway, reactor, threadpool):
        self.gateway = gateway
        super().__init__(
            WebsocketResourceDecorator(
                original=WSGIResource(reactor, threadpool, WsgiGateway(gateway)),
                websocketListener=WebSocketRequest.listener(gateway.accept),
            )
        )


class GatewaySite(Site):
    def __init__(self, gateway: Gateway):
        super().__init__(
            GatewayResource(gateway, reactor, reactor.getThreadPool()), TwistedRequestAdapter
        )
        self.protocol = HeaderPreservingHTTPChannel.protocol_factory


def serve_gateway(
    gateway: Gateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    """
    Serve a Gateway instance using twisted.
    """
    # setup reactor
    reactor.suggestThreadPoolSize(config.GATEWAY_WORKER_COUNT)
    thread_pool = reactor.getThreadPool()
    patch(thread_pool.stop)(stop_thread_pool)

    def _shutdown_reactor():
        LOG.debug("[shutdown] Shutting down twisted reactor serving the gateway")
        thread_pool.stop(timeout=10)
        reactor.stop()

    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.register(_shutdown_reactor)

    # setup twisted webserver Site
    site = GatewaySite(gateway)

    # configure ssl
    if use_ssl:
        install_predefined_cert_if_available()
        serial_number = listen[0].port
        _, cert_file_name, key_file_name = create_ssl_cert(serial_number=serial_number)
        context_factory = ssl.DefaultOpenSSLContextFactory(key_file_name, cert_file_name)
        context_factory.getContext().use_certificate_chain_file(cert_file_name)
        protocol_factory = TLSMultiplexerFactory(context_factory, False, site)
    else:
        protocol_factory = site

    # setup endpoints context
    for host_and_port in listen:
        # TODO: interface = host?
        endpoint = endpoints.TCP4ServerEndpoint(reactor, host_and_port.port)
        endpoint.listen(protocol_factory)

    if asynchronous:
        return start_worker_thread(reactor.run)
    else:
        return reactor.run()
