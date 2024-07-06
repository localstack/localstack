"""A set of common handlers to build an AWS server application."""

from .. import chain
from . import (
    analytics,
    auth,
    codec,
    cors,
    fallback,
    internal,
    internal_requests,
    legacy,
    logging,
    openapi,
    presigned_url,
    region,
    service,
)

handle_runtime_shutdown = internal.RuntimeShutdownHandler()
enforce_cors = cors.CorsEnforcer()
preprocess_request = chain.CompositeHandler()
add_cors_response_headers = cors.CorsResponseEnricher()
content_decoder = codec.ContentDecoder()
parse_service_name = service.ServiceNameParser()
parse_service_request = service.ServiceRequestParser()
add_account_id = auth.AccountIdEnricher()
inject_auth_header_if_missing = auth.MissingAuthHeaderInjector()
add_region_from_header = region.RegionContextEnricher()
add_internal_request_params = internal_requests.InternalRequestParamsEnricher()
validate_request_schema = openapi.OpenAPIRequestValidator()
validate_response_schema = openapi.OpenAPIResponseValidator()
log_exception = logging.ExceptionLogger()
log_response = logging.ResponseLogger()
count_service_request = analytics.ServiceRequestCounter()
handle_service_exception = service.ServiceExceptionSerializer()
handle_internal_failure = fallback.InternalFailureHandler()
serve_custom_service_request_handlers = chain.CompositeHandler()
serve_localstack_resources = internal.LocalstackResourceHandler()
run_custom_response_handlers = chain.CompositeResponseHandler()
modify_service_response = service.ServiceResponseHandlers()
parse_service_response = service.ServiceResponseParser()
parse_pre_signed_url_request = presigned_url.ParsePreSignedUrlRequest()
run_custom_finalizers = chain.CompositeFinalizer()
serve_custom_exception_handlers = chain.CompositeExceptionHandler()
# legacy compatibility handlers
serve_edge_router_rules = legacy.EdgeRouterHandler()
set_close_connection_header = legacy.set_close_connection_header
