import logging
from typing import Dict

from localstack import config
from localstack.aws import handlers
from localstack.aws.handlers.service_plugin import ServiceLoader
from localstack.services.plugins import SERVICE_PLUGINS, ServiceManager, ServicePluginManager

from .gateway import Gateway
from .handlers.fallback import EmptyResponseHandler
from .handlers.service import ServiceRequestRouter

LOG = logging.getLogger(__name__)


def _patch_skeleton_on_service_exception():
    def patch_on_service_exception(target, self, context, exception):
        if context.service_operation:
            ops = LocalstackAwsGateway.metric_recorder[context.service_operation.service][
                context.service_operation.operation
            ]
            errors = ops.setdefault("errors", {})
            if exception.code not in errors:
                # some errors are not explicitly in the shape, but are wrapped in a "CommonServiceException"
                errors = ops.setdefault("errors_not_in_shape", {})
            errors[exception.code] = ops.get(exception.code, 0) + 1
        return target(self, context, exception)

    from localstack.aws.skeleton import Skeleton
    from localstack.utils.patch import Patch

    patch = Patch.function(
        Skeleton.on_service_exception,
        patch_on_service_exception,
        pass_target=True,
    )
    patch.apply()


def _init_service_metric_counter() -> Dict:

    if not config.is_local_test_mode():
        return {}

    metric_recorder = {}
    from localstack.aws.spec import load_service

    for s in SERVICE_PLUGINS.list_available():
        try:
            service = load_service(s)
            ops = {}
            for op in service.operation_names:
                params = {}
                if hasattr(service.operation_model(op).input_shape, "members"):
                    for n in service.operation_model(op).input_shape.members:
                        params[n] = 0
                if hasattr(service.operation_model(op), "error_shapes"):
                    exceptions = {}
                    for e in service.operation_model(op).error_shapes:
                        exceptions[e.name] = 0
                    params["errors"] = exceptions
                ops[op] = params

            metric_recorder[s] = ops
        except Exception:
            LOG.debug(f"cannot load service '{s}'")

    # apply a patch so that we can count the service exceptions
    _patch_skeleton_on_service_exception()
    return metric_recorder


class LocalstackAwsGateway(Gateway):
    metric_recorder = _init_service_metric_counter()
    node_id = None

    def __init__(self, service_manager: ServiceManager = None) -> None:
        super().__init__()

        # basic server components
        self.service_manager = service_manager or ServicePluginManager()
        self.service_request_router = ServiceRequestRouter()
        # lazy-loads services into the router
        load_service = ServiceLoader(self.service_manager, self.service_request_router)

        # the main request handler chain
        self.request_handlers.extend(
            [
                handlers.push_request_context,
                handlers.parse_service_name,  # enforce_cors and content_decoder depend on the service name
                handlers.enforce_cors,
                handlers.content_decoder,
                handlers.serve_localstack_resources,  # try to serve internal resources in /_localstack first
                handlers.serve_default_listeners,  # legacy proxy default listeners
                handlers.serve_edge_router_rules,
                # start aws handler chain
                handlers.inject_auth_header_if_missing,
                handlers.add_region_from_header,
                handlers.add_default_account_id,
                handlers.parse_service_request,
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
                handlers.run_custom_response_handlers,
                handlers.add_cors_response_headers,
                handlers.log_response,
                handlers.pop_request_context,
            ]
        )

    def post_process(self, context, response):
        if config.is_local_test_mode():
            if context.service_operation:
                ops = LocalstackAwsGateway.metric_recorder[context.service_operation.service][
                    context.service_operation.operation
                ]
                if not context.service_request:
                    ops["none"] = ops.get("none", 0) + 1
                else:
                    for p in context.service_request:
                        # some params seem to be set implicitly but have 'None' value
                        if context.service_request[p] is not None:
                            ops[p] += 1

                test_list = ops.setdefault("tests", [])
                if LocalstackAwsGateway.node_id not in test_list:
                    test_list.append(LocalstackAwsGateway.node_id)

            # TODO collect error responses here? Already collect service exceptions


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
