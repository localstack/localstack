from localstack.http.hypercorn import GatewayServer
from localstack.runtime.shutdown import SHUTDOWN_HANDLERS
from localstack.services.plugins import SERVICE_PLUGINS


def serve_gateway(bind_address, port, use_ssl, asynchronous=False):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    from localstack.aws.app import LocalstackAwsGateway

    gateway = LocalstackAwsGateway(SERVICE_PLUGINS)

    # start serving gateway
    server = GatewayServer(gateway, port, bind_address, use_ssl)
    server.start()

    # with the current way the infrastructure is started, this is the easiest way to shut down the server correctly
    # FIXME: but the infrastructure shutdown should be much cleaner, core components like the gateway should be handled
    #  explicitly by the thing starting the components, not implicitly by the components.
    SHUTDOWN_HANDLERS.register(server.shutdown)

    if not asynchronous:
        server.join()

    return server._thread
