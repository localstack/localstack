import asyncio
import threading
from asyncio import AbstractEventLoop

from hypercorn import Config
from hypercorn.asyncio import serve
from hypercorn.typing import ASGI3Framework

from localstack.utils.serving import Server


class HypercornServer(Server):
    """
    A sync wrapper around Hypercorn that implements the ``Server`` interface.
    """

    def __init__(self, app: ASGI3Framework, config: Config, loop: AbstractEventLoop = None):
        """
        Create a new Hypercorn server instance.

        :param app: the ASGI3 app
        :param config: the hypercorn config
        :param loop: optionally the event loop, otherwise ``asyncio.get_event_loop`` will be called
        """
        self.app = app
        self.config = config
        self.loop = loop or asyncio.get_event_loop()

        self._close = asyncio.Event()
        self._closed = threading.Event()

        parts = config.bind[0].split(":")
        if len(parts) == 1:
            # check ssl
            host = parts[0]
            port = 443 if config.ssl_enabled else 80
        else:
            host, port = parts[0], int(parts[1])

        super().__init__(port, host)

    @property
    def protocol(self):
        return "https" if self.config.ssl_enabled else "http"

    def do_run(self):
        self.loop.run_until_complete(
            serve(self.app, self.config, shutdown_trigger=self._shutdown_trigger)
        )
        self._closed.set()

    def do_shutdown(self):
        asyncio.run_coroutine_threadsafe(self._set_closed(), self.loop)
        self._closed.wait(timeout=10)

    async def _set_closed(self):
        self._close.set()

    async def _shutdown_trigger(self):
        await self._close.wait()
