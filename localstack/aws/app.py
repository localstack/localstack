import logging
import threading
from typing import Any

from localstack.aws import handlers
from localstack.http import Response
from localstack.services.plugins import (
    SERVICE_PLUGINS,
    Service,
    ServiceManager,
    ServicePluginManager,
)

from .api import RequestContext
from .chain import HandlerChain
from .gateway import Gateway
from .handlers import EmptyResponseHandler, RouterHandler
from .plugins import HandlerServiceAdapter, ServiceProvider
from .proxy import AwsApiListener, DefaultListenerHandler, LegacyPluginHandler

LOG = logging.getLogger(__name__)


class LocalstackAwsGateway(Gateway):
    def __init__(self, service_manager: ServiceManager = None) -> None:
        super().__init__()
        # basic server components
        self.service_manager = service_manager or ServicePluginManager()
        self.mutex = threading.RLock()

        # the request router used within the handler chain
        self.service_request_router = handlers.ServiceRequestRouter()

        # legacy compatibility with DEFAULT_LISTENERS
        serve_default_listeners = DefaultListenerHandler()

        from localstack.services.edge import ROUTER

        serve_custom_routes = RouterHandler(ROUTER)

        # the main request handler chain
        self.request_handlers.extend(
            [
                handlers.push_quart_context,
                handlers.serve_localstack_resources,  # try to serve internal resources first
                serve_default_listeners,
                serve_custom_routes,
                # start aws handler chain
                handlers.process_custom_service_rules,  # translate things like GET requests to SQS Queue URLs
                handlers.parse_service_name,
                handlers.inject_auth_header_if_missing,
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
                handlers.pop_quart_context,
            ]
        )

    def log_response(self, _: HandlerChain, context: RequestContext, response: Response):
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

    def require_service(self, _: HandlerChain, context: RequestContext, response: Response):
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

    def add_provider(self, provider: Any, service_name: str = None):
        if service_name is None:
            service_name = provider.service

        self.service_request_router.add_provider(provider=provider, service=service_name)


def main():
    from .serving.hypercorn import serve

    use_ssl = True
    port = 4566

    # serve the LocalStackAwsGateway in a dev app
    from localstack.utils.bootstrap import setup_logging

    setup_logging()

    if use_ssl:
        from localstack.services.generic_proxy import (
            GenericProxy,
            install_predefined_cert_if_available,
        )

        install_predefined_cert_if_available()
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        ssl_creds = (cert_file_name, key_file_name)
    else:
        ssl_creds = None

    gw = LocalstackAwsGateway(SERVICE_PLUGINS)

    serve(gw, use_reloader=True, port=port, ssl_creds=ssl_creds)


if __name__ == "__main__":
    main()
