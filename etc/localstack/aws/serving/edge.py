import asyncio

from localstack.services.plugins import SERVICE_PLUGINS


def serve_gateway(bind_address, port, use_ssl, asynchronous=False):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """
    from hypercorn import Config

    from localstack.aws.app import LocalstackAwsGateway
    from localstack.aws.serving.asgi import AsgiGateway
    from localstack.http.hypercorn import HypercornServer
    from localstack.logging.setup import setup_hypercorn_logger
    from localstack.services.generic_proxy import GenericProxy, install_predefined_cert_if_available

    # build server config
    config = Config()
    setup_hypercorn_logger(config)

    if isinstance(bind_address, str):
        bind_address = [bind_address]
    config.bind = [f"{addr}:{port}" for addr in bind_address]

    if use_ssl:
        install_predefined_cert_if_available()
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        config.certfile = cert_file_name
        config.keyfile = key_file_name

    # build gateway
    loop = asyncio.new_event_loop()
    app = AsgiGateway(LocalstackAwsGateway(SERVICE_PLUGINS), event_loop=loop)

    # start serving gateway
    server = HypercornServer(app, config, loop)
    server.start()

    if not asynchronous:
        server.join()

    return server._thread
