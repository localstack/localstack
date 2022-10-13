from typing import Any, Callable

from localstack.runtime import hooks
from localstack.utils.functions import call_safe


class ShutdownHandlers:
    """
    Register / unregister shutdown handlers. All registered shutdown handlers should execute as fast as possible.
    Blocking shutdown handlers will block infra shutdown.
    """

    def __init__(self):
        self._callbacks = []

    def register(self, shutdown_handler: Callable[[], Any]) -> None:
        """
        Register shutdown handler. Handler should not block or take more than a couple seconds.

        :param shutdown_handler: Callable without parameters
        """
        self._callbacks.append(shutdown_handler)

    def unregister(self, shutdown_handler: Callable[[], Any]) -> None:
        """
        Unregister a handler. Idempotent operation.

        :param shutdown_handler: Shutdown handler which was previously registered
        """
        try:
            self._callbacks.remove(shutdown_handler)
        except ValueError:
            pass

    def run(self) -> None:
        """
        Execute shutdown handlers in reverse order of registration.
        Should only be called once, on shutdown.
        """
        for callback in reversed(list(self._callbacks)):
            call_safe(callback)


SHUTDOWN_HANDLERS = ShutdownHandlers()


@hooks.on_infra_shutdown()
def run_shutdown_handlers():
    SHUTDOWN_HANDLERS.run()
