import asyncio
import concurrent.futures.thread
from asyncio import AbstractEventLoop
from typing import Optional

from localstack.aws.gateway import Gateway
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.http.asgi import ASGIAdapter, ASGILifespanListener
from localstack.http.websocket import WebSocketRequest


class _ThreadPool(concurrent.futures.thread.ThreadPoolExecutor):
    """
    This thread pool executor removes the threads it creates from the global ``_thread_queues`` of
    ``concurrent.futures.thread``, which joins all created threads at python exit and will block interpreter shutdown of
    any threads are still running, even if they are daemon threads.
    """

    def _adjust_thread_count(self) -> None:
        super()._adjust_thread_count()

        for t in self._threads:
            if not t.daemon:
                continue
            try:
                del concurrent.futures.thread._threads_queues[t]
            except KeyError:
                pass


class AsgiGateway:
    """
    Exposes a Gateway as an ASGI3 application. Under the hood, it uses a WsgiGateway with a threading async/sync bridge.
    """

    gateway: Gateway

    def __init__(
        self,
        gateway: Gateway,
        event_loop: Optional[AbstractEventLoop] = None,
        threads: int = 1000,
        lifespan_listener: Optional[ASGILifespanListener] = None,
        websocket_listener=None,
    ) -> None:
        self.gateway = gateway

        self.event_loop = event_loop or asyncio.get_event_loop()
        self.executor = _ThreadPool(threads, thread_name_prefix="asgi_gw")
        self.adapter = ASGIAdapter(
            WsgiGateway(gateway),
            event_loop=event_loop,
            executor=self.executor,
            lifespan_listener=lifespan_listener,
            websocket_listener=websocket_listener or WebSocketRequest.listener(gateway.accept),
        )
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

        return await self.adapter(scope, receive, send)

    def close(self):
        """
        Close the ASGIGateway by shutting down the underlying executor.
        """
        self._closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)
