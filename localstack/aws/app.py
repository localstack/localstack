import logging
import threading
from typing import Any

from localstack.aws import handlers
from localstack.aws.chain import HandlerChain
from localstack.aws.handlers import EmptyResponseHandler
from localstack.aws.plugins import HandlerServiceAdapter, ServiceProvider
from localstack.aws.proxy import DefaultListenerHandler
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
        self.service_request_router = handlers.ServiceRequestRouter()

        # the main request handler chain
        self.request_handlers.extend(
            [
                handlers.serve_localstack_resources,  # try to serve internal resources first
                DefaultListenerHandler(),  # legacy compatibility with DEFAULT_LISTENERS
                # start aws handler chain
                handlers.parse_service_name,
                handlers.add_region_from_header,
                handlers.add_default_account_id,
                handlers.parse_service_request,
                self.require_service,
                self.service_request_router,
                # if the chain is still running, set an empty response
                EmptyResponseHandler(404, b'{"message": "Not Found"}'),
            ]
        )

        # exception handlers in the chain
        self.exception_handlers.extend(
            [
                handlers.log_exception,
                handlers.handle_service_exception,
                handlers.handle_internal_failure,
            ]
        )

        # response post-processing
        self.response_handlers.extend(
            [
                self.log_response,
            ]
        )

    def log_response(self, _: HandlerChain, context: RequestContext, response: HttpResponse):
        if context.operation:
            # TODO: log analytics event here
            LOG.info(
                "%s %s.%s => %d",
                context.request.method,
                context.service.service_name,
                context.operation.name,
                response.status_code,
            )
        else:
            LOG.info(
                "%s %s => %d",
                context.request.method,
                context.request.path,
                response.status_code,
            )

    def require_service(self, _: HandlerChain, context: RequestContext, response: HttpResponse):
        request_router = self.service_request_router

        if not context.service:
            return

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

            if isinstance(service_plugin, ServiceProvider):
                request_router.add_provider(service_plugin.listener)
            elif isinstance(service_plugin, HandlerServiceAdapter):
                request_router.add_handler(service_operation, service_plugin.listener)
            elif isinstance(service_plugin, Service):
                request_router.add_handler(service_operation, handlers.LegacyPluginHandler())
            else:
                LOG.warning(
                    "found plugin for %s, but cannot attach service plugin of type %s",
                    service_name,
                    type(service_plugin),
                )

    def add_provider(self, provider: Any, service_name: str = None):
        if service_name is None:
            service_name = provider.service

        self.service_request_router.add_provider(provider=provider, service=service_name)


def main():
    from .serving import wsgi

    # serve the LocalStackAwsGateway in a dev app
    logging.basicConfig(level=logging.WARNING)
    gw = LocalstackAwsGateway()
    wsgi.serve(gw, use_reloader=False)


if __name__ == "__main__":
    main()
