from localstack.aws import handlers
from localstack.aws.handlers.metric_handler import MetricHandler
from localstack.aws.handlers.service_plugin import ServiceLoader
from localstack.services.plugins import SERVICE_PLUGINS, ServiceManager, ServicePluginManager

from .gateway import Gateway
from .handlers.fallback import EmptyResponseHandler
from .handlers.service import ServiceRequestRouter


class LocalstackAwsGateway(Gateway):
    def __init__(self, service_manager: ServiceManager = None) -> None:
        super().__init__()

        # basic server components
        self.service_manager = service_manager or ServicePluginManager()
        self.service_request_router = ServiceRequestRouter()
        # lazy-loads services into the router
        load_service = ServiceLoader(self.service_manager, self.service_request_router)

        metric_collector = MetricHandler()
        # the main request handler chain
        self.request_handlers.extend(
            [
                handlers.push_request_context,
                metric_collector.create_metric_handler_item,
                handlers.parse_service_name,  # enforce_cors and content_decoder depend on the service name
                handlers.enforce_cors,
                handlers.content_decoder,
                handlers.serve_localstack_resources,  # try to serve internal resources in /_localstack first
                handlers.serve_default_listeners,  # legacy proxy default listeners
                handlers.serve_edge_router_rules,
                # start aws handler chain
                handlers.inject_auth_header_if_missing,
                handlers.add_region_from_header,
                handlers.add_account_id,
                handlers.parse_service_request,
                metric_collector.record_parsed_request,
                handlers.serve_custom_service_request_handlers,
                load_service,  # once we have the service request we can make sure we load the service
                self.service_request_router,  # once we know the service is loaded we can route the request
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
                handlers.parse_service_response,
                handlers.run_custom_response_handlers,
                handlers.add_cors_response_headers,
                handlers.log_response,
                handlers.count_service_request,
                handlers.pop_request_context,
                metric_collector.update_metric_collection,
            ]
        )


def main():
    """
    Serve the LocalstackGateway with the default configuration directly through hypercorn. This is mostly for
    development purposes and documentation on how to serve the Gateway.
    """
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
