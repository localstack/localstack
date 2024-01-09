import logging
from typing import List

from localstack import config
from localstack.config import HostAndPort
from localstack.http.hypercorn import GatewayServer
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.services.plugins import SERVICE_PLUGINS

LOG = logging.getLogger(__name__)


def serve_gateway(
    listen: HostAndPort | List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    from localstack.aws.app import LocalstackAwsGateway

    gateway = LocalstackAwsGateway(SERVICE_PLUGINS)

    # start serving gateway
    server = GatewayServer(gateway, listen, use_ssl, config.GATEWAY_WORKER_COUNT)
    server.start()

    # with the current way the infrastructure is started, this is the easiest way to shut down the server correctly
    # FIXME: but the infrastructure shutdown should be much cleaner, core components like the gateway should be handled
    #  explicitly by the thing starting the components, not implicitly by the components.
    def _shutdown_gateway():
        LOG.debug("[shutdown] Shutting down gateway server")
        server.shutdown()

    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.register(_shutdown_gateway)

    if not asynchronous:
        server.join()

    return server._thread
