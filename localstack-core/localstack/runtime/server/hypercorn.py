import asyncio
import threading

from hypercorn import Config
from hypercorn.asyncio import serve
from rolo.gateway import Gateway
from rolo.gateway.asgi import AsgiGateway

from localstack import config
from localstack.logging.setup import setup_hypercorn_logger

from .core import RuntimeServer


class HypercornRuntimeServer(RuntimeServer):
    def __init__(self):
        self.loop = asyncio.get_event_loop()

        self._close = asyncio.Event()
        self._closed = threading.Event()

        self._futures = []

    def register(
        self,
        gateway: Gateway,
        listen: list[config.HostAndPort],
        ssl_creds: tuple[str, str] | None = None,
    ):
        hypercorn_config = Config()
        hypercorn_config.h11_pass_raw_headers = True
        hypercorn_config.bind = [str(host_and_port) for host_and_port in listen]
        # hypercorn_config.use_reloader = use_reloader

        setup_hypercorn_logger(hypercorn_config)

        if ssl_creds:
            cert_file_name, key_file_name = ssl_creds
            hypercorn_config.certfile = cert_file_name
            hypercorn_config.keyfile = key_file_name

        app = AsgiGateway(gateway, event_loop=self.loop)

        future = asyncio.run_coroutine_threadsafe(
            serve(app, hypercorn_config, shutdown_trigger=self._shutdown_trigger),
            self.loop,
        )
        self._futures.append(future)

    def run(self):
        self.loop.run_forever()

    def shutdown(self):
        self._close.set()
        asyncio.run_coroutine_threadsafe(self._set_closed(), self.loop)
        # TODO: correctly wait for all hypercorn serve coroutines to finish
        asyncio.run_coroutine_threadsafe(self.loop.shutdown_asyncgens(), self.loop)
        self.loop.shutdown_default_executor()
        self.loop.stop()

    async def _wait_server_stopped(self):
        self._closed.set()

    async def _set_closed(self):
        self._close.set()

    async def _shutdown_trigger(self):
        await self._close.wait()
