import logging
import threading
from typing import Any

from localstack.aws import handlers
from localstack.aws.chain import HandlerChain
from localstack.aws.plugins import HandlerServiceAdapter, ServiceProvider
from localstack.services.plugins import Service, ServiceManager, ServicePluginManager

from .api import HttpResponse, RequestContext
from .gateway import Gateway

LOG = logging.getLogger(__name__)


class LocalstackAwsGateway(Gateway):
    def __init__(self, service_manager: ServiceManager = None) -> None:
        super().__init__()
        # basic server components
        self.service_manager = service_manager or ServicePluginManager()
        self.mutex = threading.RLock()

        # the request router used within the handler chain
        self.request_router = handlers.ServiceRequestRouter()

        # the main handler chain
        self.request_handlers.extend(
            [
                handlers.parse_service_name,
                handlers.add_region_from_header,
                handlers.add_default_account_id,
                handlers.parse_service_request,
                self.require_route,
                self.route_request,
                self.log_response,
            ]
        )

        # exception handlers in the chain
        self.exception_handlers.extend(
            [
                handlers.log_exception,
                handlers.return_serialized_exception,
            ]
        )

    def log_response(self, _: HandlerChain, context: RequestContext, response: HttpResponse):
        # TODO: log analytics event here
        LOG.info(
            "Response(%s.%s,%d)",
            context.service.service_name,
            context.operation.name,
            response.get("status_code", 0),
        )

    def require_route(self, _: HandlerChain, context: RequestContext, response: HttpResponse):
        # verify that we have a route for this request
        service_operation = context.service_operation
        if service_operation in self.request_router.handlers:
            return

        # FIXME: this blocks all requests to other services, so a mutex list per-service would be useful
        with self.mutex:
            # try again to avoid race conditions
            if service_operation in self.request_router.handlers:
                return

            service_name = context.service.service_name
            service_plugin: Service = self.service_manager.require(service_name)

            if isinstance(service_plugin, ServiceProvider):
                self.request_router.add_provider(service_plugin.listener)
            elif isinstance(service_plugin, HandlerServiceAdapter):
                self.request_router.add_handler(service_operation, service_plugin.listener)
            elif isinstance(service_plugin, Service):
                self.request_router.add_handler(service_operation, handlers.LegacyPluginHandler())
            else:
                LOG.warning(
                    "found plugin for %s, but cannot attach service plugin of type %s",
                    service_name,
                    type(service_plugin),
                )

    def route_request(self, chain: HandlerChain, context: RequestContext, response: HttpResponse):
        self.request_router(chain, context, response)

    def add_provider(self, provider: Any, service_name: str = None):
        if service_name is None:
            service_name = provider.service

        self.request_router.add_provider(provider=provider, service=service_name)


def main():
    from .serving import wsgi

    # serve the LocalStackAwsGateway in a dev app
    logging.basicConfig(level=logging.WARNING)
    gw = LocalstackAwsGateway()
    wsgi.serve(gw, use_reloader=False)


if __name__ == "__main__":
    main()
