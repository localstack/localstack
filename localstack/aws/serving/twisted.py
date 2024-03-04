"""
Bindings to serve LocalStack using twisted.web.wsgi.

TODO: both header retaining and TLS multiplexing are implemented in a pretty hacky way.
"""
import logging
from typing import TYPE_CHECKING, List

from rolo.gateway import Gateway
from twisted.internet import endpoints, interfaces, reactor, ssl
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
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

# TODO: websockets


def update_environment(environ: "WSGIEnvironment", request: TwistedRequest):
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
    # TODO: check if this is correct
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
    rawHeaderList: list[tuple[bytes, bytes]]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # instantiate case mappings, these are used by `getAllRawHeaders` to restore casing
        # by default, they are class attributes, so we would override them globally
        self.requestHeaders._caseMappings = dict(self.requestHeaders._caseMappings)
        self.responseHeaders._caseMappings = dict(self.responseHeaders._caseMappings)


class HeaderPreservingHTTPChannel(HTTPChannel):
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
        try:
            # will be TLSMultiplexer
            return self.transport.isSecure()
        except AttributeError:
            return super().isSecure()


class TLSMultiplexer(TLSMemoryBIOProtocol):
    def __init__(
        self,
        factory: TLSMemoryBIOFactory,
        wrappedProtocol: interfaces.IProtocol,
        _connectWrapped: bool = True,
    ):
        super().__init__(factory, wrappedProtocol, _connectWrapped)
        self._isInitialized = False
        self._isTLS = False
        self._protocol = None

    def isSecure(self):
        return self._isTLS

    def dataReceived(self, data):
        if self._isInitialized:
            raise ValueError("Should not call this method once initialized")

        self._isInitialized = True
        self._isTLS = data[0] == 22

        if self._isTLS:
            self.dataReceived = super().dataReceived
            self.write = super().write
        else:
            # TODO: can we do proper protocol negotiation like in ALPN?
            if data.startswith(b"PRI * HTTP/2"):
                self._protocol = b"h2"

            # foregoes TLS wrapper
            self.dataReceived = self.wrappedProtocol.dataReceived
            self.write = self.transport.write

        self.dataReceived(data)

    @property
    def negotiatedProtocol(self):
        if self._protocol:
            return self._protocol
        return super().negotiatedProtocol


class TLSMultiplexerFactory(TLSMemoryBIOFactory):
    protocol = TLSMultiplexer


def serve_gateway(
    gateway: Gateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    # setup reactor
    reactor.suggestThreadPoolSize(config.GATEWAY_WORKER_COUNT)
    thread_pool = reactor.getThreadPool()

    def _shutdown_reactor():
        LOG.debug("[shutdown] Shutting down twisted reactor serving the gateway")
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
