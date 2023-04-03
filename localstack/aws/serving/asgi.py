import asyncio
import concurrent.futures.thread
from asyncio import AbstractEventLoop
from typing import TYPE_CHECKING, Optional

from localstack.aws.gateway import Gateway
from localstack.aws.serving.wsgi import WsgiGateway
from localstack.http.asgi import ASGIAdapter, ASGILifespanListener

if TYPE_CHECKING:
    from hypercorn.typing import ASGIReceiveCallable, ASGISendCallable, HTTPScope


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
    ) -> None:
        self.gateway = gateway

        self.event_loop = event_loop or asyncio.get_event_loop()
        self.executor = _ThreadPool(threads, thread_name_prefix="asgi_gw")
        self.wsgi = ASGIAdapter(WsgiGateway(gateway), event_loop=event_loop, executor=self.executor)
        self.lifespan_listener = lifespan_listener or ASGILifespanListener()
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

        if scope["type"] == "lifespan":
            return await self.handle_lifespan(scope, receive, send)

        raise NotImplementedError(f"{scope['type']} protocol is not implemented")

    def close(self):
        """
        Close the ASGIGateway by shutting down the underlying executor.
        """
        self._closed = True
        self.executor.shutdown(wait=False, cancel_futures=True)

    async def handle_lifespan(
        self, scope: "HTTPScope", receive: "ASGIReceiveCallable", send: "ASGISendCallable"
    ):
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    await self.event_loop.run_in_executor(
                        self.executor, self.lifespan_listener.on_startup
                    )
                    await send({"type": "lifespan.startup.complete"})
                except Exception as e:
                    await send({"type": "lifespan.startup.failed", "message": f"{e}"})

            elif message["type"] == "lifespan.shutdown":
                try:
                    await self.event_loop.run_in_executor(
                        self.executor, self.lifespan_listener.on_shutdown
                    )
                    await send({"type": "lifespan.shutdown.complete"})
                except Exception as e:
                    await send({"type": "lifespan.shutdown.failed", "message": f"{e}"})
                return
            else:
                return
