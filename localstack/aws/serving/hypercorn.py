import asyncio
from typing import Any, Optional, Tuple

from hypercorn import Config
from hypercorn.asyncio import serve as serve_hypercorn

from localstack import constants

from ..gateway import Gateway
from .asgi import AsgiGateway


def serve(
    gateway: Gateway,
    host: str = "localhost",
    port: int = constants.DEFAULT_PORT_EDGE,
    use_reloader: bool = True,
    ssl_creds: Optional[Tuple[Any, Any]] = None,
    **kwargs,
) -> None:
    """
    Serve the given Gateway through a hypercorn server and block until it is completed.

    :param gateway: the Gateway instance to serve
    :param host: the host to expose the server on
    :param port: the port to expose the server on
    :param use_reloader: whether to use the reloader
    :param ssl_creds: the ssl credentials (tuple of certfile and keyfile)
    :param kwargs: any oder parameters that can be passed to the hypercorn.Config object
    """
    config = Config()
    config.h11_pass_raw_headers = True
    config.bind = f"{host}:{port}"
    config.use_reloader = use_reloader

    if ssl_creds:
        cert_file_name, key_file_name = ssl_creds
        if cert_file_name:
            kwargs["certfile"] = cert_file_name
        if key_file_name:
            kwargs["keyfile"] = key_file_name

    for k, v in kwargs.items():
        setattr(config, k, v)

    loop = asyncio.new_event_loop()
    loop.run_until_complete(serve_hypercorn(AsgiGateway(gateway, event_loop=loop), config))
