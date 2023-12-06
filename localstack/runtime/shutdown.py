import logging
from typing import Any, Callable

from localstack.runtime import hooks
from localstack.utils.functions import call_safe

LOG = logging.getLogger(__name__)

SERVICE_SHUTDOWN_PRIORITY = -10
"""Shutdown hook priority for shutting down service plugins."""


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
"""Shutdown handlers run with default priority in an on_infra_shutdown hook."""

ON_AFTER_SERVICE_SHUTDOWN_HANDLERS = ShutdownHandlers()
"""Shutdown handlers that are executed after all services have been shut down."""


@hooks.on_infra_shutdown()
def run_shutdown_handlers():
    SHUTDOWN_HANDLERS.run()


@hooks.on_infra_shutdown(priority=SERVICE_SHUTDOWN_PRIORITY)
def shutdown_services():
    # TODO: this belongs into the shutdown procedure of a `Platform` or `RuntimeContainer` class.
    from localstack.services.plugins import SERVICE_PLUGINS

    LOG.info("[shutdown] Stopping all services")
    SERVICE_PLUGINS.stop_all_services()


@hooks.on_infra_shutdown(priority=SERVICE_SHUTDOWN_PRIORITY - 10)
def run_on_after_service_shutdown_handlers():
    ON_AFTER_SERVICE_SHUTDOWN_HANDLERS.run()
