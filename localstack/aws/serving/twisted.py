"""
Bindings to serve LocalStack using twisted.
"""

import logging
import time
from typing import List

from rolo.gateway import Gateway
from rolo.serving.twisted import TwistedGateway
from twisted.internet import endpoints, interfaces, reactor, ssl
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.protocols.tls import BufferingTLSTransport, TLSMemoryBIOFactory
from twisted.python.threadpool import ThreadPool

from localstack import config
from localstack.config import HostAndPort
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.utils.patch import patch
from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)


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
    site = TwistedGateway(gateway)

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

    # add endpoint for each host/port combination
    for host_and_port in listen:
        # TODO: interface = host?
        endpoint = endpoints.TCP4ServerEndpoint(reactor, host_and_port.port)
        endpoint.listen(protocol_factory)

    if asynchronous:
        return start_worker_thread(reactor.run)
    else:
        return reactor.run()
