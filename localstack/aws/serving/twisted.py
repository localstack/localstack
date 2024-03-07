"""
Bindings to serve LocalStack using ``twisted.web``.

TODO: both header retaining and TLS multiplexing are implemented in a pretty hacky way.
TODO: websocket support
"""
import logging
import time
from typing import TYPE_CHECKING, List

from rolo.gateway import Gateway
from twisted.internet import endpoints, interfaces, reactor, ssl
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.protocols.tls import BufferingTLSTransport, TLSMemoryBIOFactory
from twisted.python.threadpool import ThreadPool
from twisted.web.http import HTTPChannel, _GenericHTTPChannelProtocol
from twisted.web.server import Request as TwistedRequest
from twisted.web.server import Site
from twisted.web.wsgi import WSGIResource, _WSGIResponse

from localstack import config
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.config import HostAndPort
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.utils.patch import patch
from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available
from localstack.utils.threads import start_worker_thread

if TYPE_CHECKING:
    from _typeshed.wsgi import WSGIEnvironment

LOG = logging.getLogger(__name__)


def update_environment(environ: "WSGIEnvironment", request: TwistedRequest):
    """
    Update the pre-populated WSGI environment with additional data, needed by rolo, from the webserver request object.

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
    Patch to populate the environment with additional variables we need in LocalStack that the server is not setting by
    default.
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
    Special HTTPChannel implementation that uses ``Headers._caseMappings`` to retain header casing both for request
    headers (server -> WSGI), and  response headers (WSGI -> client).
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
    ``DuplexSocket``, but since twisted use its own SSL layer and doesn't use `ssl.SSLSocket``, we need to implement
    the multiplexing behavior in the Twisted layer.

    The basic idea is to defer the ``makeConnection`` call until the first data are received, and then re-configure
    the underlying ``wrappedProtocol`` if needed with a TLS wrapper.
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

        # once the first data have been received, we can check whether it's a TLS handshake, then we need to run the
        # actual makeConnection procedure.
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
    wsgi = WsgiGateway(gateway)
    resource = WSGIResource(reactor, thread_pool, wsgi)
    site = Site(resource)
    site.protocol = HeaderPreservingHTTPChannel.protocol_factory
    site.requestFactory = TwistedRequestAdapter

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
