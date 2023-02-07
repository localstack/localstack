from asyncio import AbstractEventLoop
from typing import Optional

from localstack.aws.gateway import Gateway
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.http.asgi import ASGIAdapter
from localstack.utils.executor import DaemonThreadPool


class AsgiGateway:
    """
    Exposes a Gateway as an ASGI3 application. Under the hood, it uses a WsgiGateway with a threading async/sync bridge.
    """

    gateway: Gateway

    def __init__(
        self, gateway: Gateway, event_loop: Optional[AbstractEventLoop] = None, threads: int = 1000
    ) -> None:
        self.gateway = gateway

        self.executor = DaemonThreadPool(threads, thread_name_prefix="asgi_gw")
        self.wsgi = ASGIAdapter(WsgiGateway(gateway), event_loop=event_loop, executor=self.executor)
        self._closed = False

    async def __call__(self, scope, receive, send) -> None:
        """
        ASGI3 application interface.

        :param scope: the ASGI request scope
        :param receive: the receive callable
        :param send: the send callable
        """
        if self._closed:
            raise RuntimeError("Cannot except new request on closed ASGIGateway")

        if scope["type"] == "http":
            return await self.wsgi(scope, receive, send)

        raise NotImplementedError(f"{scope['type']} protocol is not implemented")

    def close(self):
        """
        Close the ASGIGateway by shutting down the underlying executor.
        """
        self._closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)
