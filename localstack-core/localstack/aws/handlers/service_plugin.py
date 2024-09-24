"""Handlers extending the base logic of service handlers with lazy-loading and plugin mechanisms."""

import logging
import threading

from localstack.http import Response
from localstack.services.plugins import Service, ServiceManager
from localstack.utils.sync import SynchronizedDefaultDict

from ...utils.bootstrap import is_api_enabled
from ..api import RequestContext
from ..chain import Handler, HandlerChain
from ..protocol.service_router import determine_aws_service_model_for_data_plane
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
        self.loaded_services = set()

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        return self.require_service(chain, context, response)

    def require_service(self, _: HandlerChain, context: RequestContext, response: Response):
        if not context.service:
            return

        service_name: str = context.service.service_name
        if service_name in self.loaded_services:
            return

        if not self.service_manager.exists(service_name):
            raise NotImplementedError
        elif not is_api_enabled(service_name):
            raise NotImplementedError(
                f"Service '{service_name}' is not enabled. Please check your 'SERVICES' configuration variable."
            )

        request_router = self.service_request_router

        # Ensure the Service is loaded and set to ServiceState.RUNNING if not in an erroneous state.
        service_plugin: Service = self.service_manager.require(service_name)

        with self.service_locks[context.service.service_name]:
            # try again to avoid race conditions
            if service_name in self.loaded_services:
                return
            self.loaded_services.add(service_name)
            if isinstance(service_plugin, Service):
                request_router.add_skeleton(service_plugin.skeleton)
            else:
                LOG.warning(
                    "found plugin for '%s', but cannot attach service plugin of type '%s'",
                    service_name,
                    type(service_plugin),
                )


class ServiceLoaderForDataPlane(Handler):
    """
    Specific lightweight service loader that loads services based only on hostname indicators. This allows
    us to correctly load services when things like lambda function URLs or APIGW REST APIs are called
    before the services were actually loaded.
    """

    def __init__(self, service_loader: ServiceLoader):
        self.service_loader = service_loader

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if context.service:
            return

        if service := determine_aws_service_model_for_data_plane(context.request):
            context.service = service
            self.service_loader.require_service(chain, context, response)
