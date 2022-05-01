from asyncio import AbstractEventLoop
from concurrent.futures import ThreadPoolExecutor
from typing import Optional

from localstack.aws.gateway import Gateway
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.http.asgi import ASGIAdapter


class AsgiGateway:
    """
    Exposes a Gateway as an ASGI3 application. Under the hood, it uses a WsgiGateway with a threading async/sync bridge.
    """

    gateway: Gateway

    def __init__(
        self, gateway: Gateway, event_loop: Optional[AbstractEventLoop] = None, threads: int = 32
    ) -> None:
        self.gateway = gateway
        self.wsgi = ASGIAdapter(
            WsgiGateway(gateway), event_loop=event_loop, executor=ThreadPoolExecutor(threads)
        )

    async def __call__(self, scope, receive, send) -> None:
        """
        ASGI3 application interface.

        :param scope: the ASGI request scope
        :param receive: the receive callable
        :param send: the send callable
        """
        if scope["type"] == "http":
            return await self.wsgi(scope, receive, send)

        raise NotImplementedError(f"{scope['type']} protocol is not implemented")
