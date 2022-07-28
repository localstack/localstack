"""Handlers extending the base logic of service handlers with lazy-loading and plugin mechanisms."""
import logging
import threading

from localstack.http import Response
from localstack.services.plugins import Service, ServiceManager

from ..api import RequestContext
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
        self.mutex = threading.RLock()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        return self.require_service(chain, context, response)

    def require_service(self, _: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        request_router = self.service_request_router

        # verify that we have a route for this request
        service_operation = context.service_operation
        if service_operation in request_router.handlers:
            return

        # FIXME: this blocks all requests to other services, so a mutex list per-service would be useful
        with self.mutex:
            # try again to avoid race conditions
            if service_operation in request_router.handlers:
                return

            service_name = context.service.service_name
            if not self.service_manager.exists(service_name):
                raise NotImplementedError

            service_plugin: Service = self.service_manager.require(service_name)

            if isinstance(service_plugin, Service):
                if type(service_plugin.listener) == AwsApiListener:
                    request_router.add_skeleton(service_plugin.listener.skeleton)
                else:
                    request_router.add_handler(service_operation, LegacyPluginHandler())
            else:
                LOG.warning(
                    "found plugin for %s, but cannot attach service plugin of type %s",
                    service_name,
                    type(service_plugin),
                )
