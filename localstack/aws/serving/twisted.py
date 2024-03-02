"""Bindings to serve LocalStack using twisted.web.wsgi"""
import logging
from typing import TYPE_CHECKING, List

from rolo.gateway import Gateway
from twisted.internet import endpoints, reactor, ssl
from twisted.web.server import Request, Site
from twisted.web.wsgi import WSGIResource, _WSGIResponse

from localstack.aws.app import LocalstackAwsGateway
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.config import HostAndPort
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.services.plugins import SERVICE_PLUGINS
from localstack.utils.patch import patch
from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available
from localstack.utils.threads import start_worker_thread

if TYPE_CHECKING:
    from _typeshed.wsgi import StartResponse, WSGIApplication, WSGIEnvironment

LOG = logging.getLogger(__name__)

# TODO: duplex ssl socket
# TODO: websockets


def update_environment(environ: "WSGIEnvironment", request: Request):
    # store raw headers
    headers: list[tuple[bytes, bytes]] = []
    for k, vs in request.requestHeaders.getAllRawHeaders():
        for v in vs:
            headers.append((k, v))
    environ["asgi.headers"] = headers
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


class TwistedGatewayAdapter:
    app: "WSGIApplication"

    def __init__(self, app: "WSGIApplication"):
        self.app = app

    def __call__(self, environ: "WSGIEnvironment", start_response: "StartResponse"):
        return self.app(environ, start_response)


def serve_gateway(
    gateway: Gateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    # setup reactor
    reactor.suggestThreadPoolSize(1000)
    thread_pool = reactor.getThreadPool()

    def _shutdown_reactor():
        LOG.debug("[shutdown] Shutting down twisted reactor serving the gateway")
        reactor.stop()

    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.register(_shutdown_reactor)

    # setup twisted webserver Site
    gateway = LocalstackAwsGateway(SERVICE_PLUGINS)
    wsgi = WsgiGateway(gateway)
    resource = WSGIResource(reactor, thread_pool, TwistedGatewayAdapter(wsgi))
    site = Site(resource)

    # configure ssl
    if use_ssl:
        install_predefined_cert_if_available()
        serial_number = listen[0].port
        _, cert_file_name, key_file_name = create_ssl_cert(serial_number=serial_number)
        print(cert_file_name, key_file_name)
        context_factory = ssl.DefaultOpenSSLContextFactory(key_file_name, cert_file_name)
    else:
        context_factory = None

    # setup endpoints context
    for host_and_port in listen:
        # TODO: interface = host?
        if use_ssl:
            # TODO: duplex socket for twisted
            endpoint = endpoints.SSL4ServerEndpoint(reactor, host_and_port.port, context_factory)
        else:
            endpoint = endpoints.TCP4ServerEndpoint(reactor, host_and_port.port)

        endpoint.listen(site)

    if asynchronous:
        return start_worker_thread(reactor.run)
    else:
        return reactor.run()
