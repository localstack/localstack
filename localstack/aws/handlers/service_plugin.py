"""Handlers extending the base logic of service handlers with lazy-loading and plugin mechanisms."""
import logging
import threading
from typing import Optional

from localstack.http import Response
from localstack.services.plugins import Service, ServiceManager
from localstack.utils.sync import SynchronizedDefaultDict

from ..api import RequestContext
from ..api.core import ServiceOperation
from ..chain import Handler, HandlerChain
from ..proxy import AwsApiListener
from .legacy import LegacyPluginHandler
from .service import ServiceRequestRouter

LOG = logging.getLogger(__name__)


class ServiceLoader(Handler):
    def __init__(
        self, service_manager: ServiceManager, service_request_router: ServiceRequestRouter
    ):
        """
        This handler encapsulates service lazy-loading. It loads services from the given ServiceManager and uses them
        to populate the given ServiceRequestRouter.

        :param service_manager: the service manager used to load services
        :param service_request_router: the service request router to populate
        """
        self.service_manager = service_manager
        self.service_request_router = service_request_router
        self.service_locks = SynchronizedDefaultDict(threading.RLock)

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        return self.require_service(chain, context, response)

    def require_service(self, _: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        service_name: str = context.service.service_name
        if not self.service_manager.exists(service_name):
            raise NotImplementedError

        service_operation: Optional[ServiceOperation] = context.service_operation
        request_router = self.service_request_router

        # Ensure the Service is loaded and set to ServiceState.RUNNING if not in an erroneous state.
        service_plugin: Service = self.service_manager.require(service_name)

        # Continue adding service skelethon and handlers to the router if these are missing.
        if service_operation in request_router.handlers:
            return

        with self.service_locks[context.service.service_name]:
            # try again to avoid race conditions
            if service_operation in request_router.handlers:
                return
            if isinstance(service_plugin, Service):
                if type(service_plugin.listener) == AwsApiListener:
                    request_router.add_skeleton(service_plugin.listener.skeleton)
                else:
                    request_router.add_handler(service_operation, LegacyPluginHandler())
            else:
                LOG.warning(
                    f"found plugin for '{service_name}', "
                    f"but cannot attach service plugin of type '{type(service_plugin)}'",
                )
