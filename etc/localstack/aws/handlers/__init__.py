""" A set of common handlers to build an AWS server application."""

from .. import chain
from . import analytics, auth, codec, cors, fallback, internal, legacy, logging, region, service

enforce_cors = cors.CorsEnforcer()
add_cors_response_headers = cors.CorsResponseEnricher()
content_decoder = codec.ContentDecoder()
parse_service_name = service.ServiceNameParser()
parse_service_request = service.ServiceRequestParser()
add_account_id = auth.AccountIdEnricher()
inject_auth_header_if_missing = auth.MissingAuthHeaderInjector()
add_region_from_header = region.RegionContextEnricher()
log_exception = logging.ExceptionLogger()
log_response = logging.ResponseLogger()
count_service_request = analytics.ServiceRequestCounter()
handle_service_exception = service.ServiceExceptionSerializer()
handle_internal_failure = fallback.InternalFailureHandler()
serve_custom_service_request_handlers = chain.CompositeHandler()
serve_localstack_resources = internal.LocalstackResourceHandler()
run_custom_response_handlers = chain.CompositeResponseHandler()
parse_service_response = service.ServiceResponseParser()
# legacy compatibility handlers
serve_edge_router_rules = legacy.EdgeRouterHandler()
serve_default_listeners = legacy.DefaultListenerHandler()
pop_request_context = legacy.pop_request_context
push_request_context = legacy.push_request_context
