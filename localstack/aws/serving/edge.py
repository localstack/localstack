from localstack.http.hypercorn import GatewayServer
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

    if not asynchronous:
        server.join()

    return server._thread
