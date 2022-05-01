import asyncio
from typing import Any, Optional, Tuple

from hypercorn import Config
from hypercorn.asyncio import serve as serve_hypercorn

from ..gateway import Gateway
from .asgi import AsgiGateway


def serve(
    gateway: Gateway,
    host: str = "localhost",
    port: int = 4566,
    use_reloader: bool = True,
    ssl_creds: Optional[Tuple[Any, Any]] = None,
    **kwargs,
):
    config = Config()
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

    loop = asyncio.get_event_loop()
    loop.run_until_complete(serve_hypercorn(AsgiGateway(gateway, event_loop=loop), config))
