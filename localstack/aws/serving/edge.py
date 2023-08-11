from localstack.http.hypercorn import GatewayServer
from localstack.runtime.shutdown import SHUTDOWN_HANDLERS


def serve_gateway(bind_address, port, use_ssl, asynchronous=False):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    from localstack.runtime import components

    # start serving gateway
    server = GatewayServer(components.gateway, port, bind_address, use_ssl)
    server.start()

    # with the current way the infrastructure is started, this is the easiest way to shut down the server correctly
    # FIXME: but the infrastructure shutdown should be much cleaner, core components like the gateway should be handled
    #  explicitly by the thing starting the components, not implicitly by the components.
    SHUTDOWN_HANDLERS.register(server.shutdown)

    if not asynchronous:
        server.join()

    return server._thread
