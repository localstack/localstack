import logging
import threading
from typing import List

from rolo.gateway.wsgi import WsgiGateway

from localstack import config
from localstack.aws.app import LocalstackAwsGateway
from localstack.config import HostAndPort
from localstack.runtime import get_current_runtime
from localstack.runtime.shutdown import ON_AFTER_SERVICE_SHUTDOWN_HANDLERS
from localstack.utils.collections import ensure_list

LOG = logging.getLogger(__name__)


def serve_gateway(
    listen: HostAndPort | List[HostAndPort], use_ssl: bool, asynchronous: bool = False
):
    """
    Implementation of the edge.do_start_edge_proxy interface to start a Hypercorn server instance serving the
    LocalstackAwsGateway.
    """

    gateway = get_current_runtime().components.gateway

    listens = ensure_list(listen)

    if config.GATEWAY_SERVER == "hypercorn":
        return _serve_hypercorn(gateway, listens, use_ssl, asynchronous)
    elif config.GATEWAY_SERVER == "werkzeug":
        return _serve_werkzeug(gateway, listens, use_ssl, asynchronous)
    elif config.GATEWAY_SERVER == "twisted":
        return _serve_twisted(gateway, listens, use_ssl, asynchronous)
    else:
        raise ValueError(f"Unknown gateway server type {config.GATEWAY_SERVER}")


def _serve_werkzeug(
    gateway: LocalstackAwsGateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool
):
    from werkzeug.serving import ThreadedWSGIServer

    from .werkzeug import CustomWSGIRequestHandler

    params = {
        "app": WsgiGateway(gateway),
        "handler": CustomWSGIRequestHandler,
    }

    if use_ssl:
        from localstack.utils.ssl import create_ssl_cert, install_predefined_cert_if_available

        install_predefined_cert_if_available()
        serial_number = listen[0].port
        _, cert_file_name, key_file_name = create_ssl_cert(serial_number=serial_number)
        params["ssl_context"] = (cert_file_name, key_file_name)

    threads = []
    servers: List[ThreadedWSGIServer] = []

    for host_port in listen:
        kwargs = dict(params)
        kwargs["host"] = host_port.host
        kwargs["port"] = host_port.port
        server = ThreadedWSGIServer(**kwargs)
        servers.append(server)
        threads.append(
            threading.Thread(
                target=server.serve_forever, name=f"werkzeug-server-{host_port.port}", daemon=True
            )
        )

    def _shutdown_servers():
        LOG.debug("[shutdown] Shutting down gateway servers")
        for _srv in servers:
            _srv.shutdown()

    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.register(_shutdown_servers)

    for thread in threads:
        thread.start()

    if not asynchronous:
        for thread in threads:
            return thread.join()

    # FIXME: thread handling is a bit wonky
    return threads[0]


def _serve_hypercorn(
    gateway: LocalstackAwsGateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool
):
    from localstack.http.hypercorn import GatewayServer

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


def _serve_twisted(
    gateway: LocalstackAwsGateway, listen: List[HostAndPort], use_ssl: bool, asynchronous: bool
):
    from .twisted import serve_gateway

    return serve_gateway(gateway, listen, use_ssl, asynchronous)
