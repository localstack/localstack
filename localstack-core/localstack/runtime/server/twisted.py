from rolo.gateway import Gateway
from rolo.serving.twisted import TwistedGateway
from twisted.internet import endpoints, reactor, ssl

from localstack import config
from localstack.aws.serving.twisted import TLSMultiplexerFactory, stop_thread_pool
from localstack.utils import patch

from .core import RuntimeServer


class TwistedRuntimeServer(RuntimeServer):
    def __init__(self):
        self.thread_pool = None

    def register(
        self,
        gateway: Gateway,
        listen: list[config.HostAndPort],
        ssl_creds: tuple[str, str] | None = None,
    ):
        # setup twisted webserver Site
        site = TwistedGateway(gateway)

        # configure ssl
        if ssl_creds:
            cert_file_name, key_file_name = ssl_creds
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

    def run(self):
        reactor.suggestThreadPoolSize(config.GATEWAY_WORKER_COUNT)
        self.thread_pool = reactor.getThreadPool()
        patch.patch(self.thread_pool.stop)(stop_thread_pool)

        # we don't need signal handlers, since all they do is call ``reactor`` stop, which we expect the
        # caller to do via ``shutdown``.
        return reactor.run(installSignalHandlers=False)

    def shutdown(self):
        if self.thread_pool:
            self.thread_pool.stop(timeout=10)
        reactor.stop()
