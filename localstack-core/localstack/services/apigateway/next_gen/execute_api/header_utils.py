import logging
from collections import defaultdict
from typing import Iterable

from werkzeug.datastructures.headers import Headers

from localstack.aws.api.apigateway import IntegrationType
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import InternalServerError
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

# Headers dropped at the request parsing. They will never make it to the invocation requests.
# And won't be available for request mapping.
DROPPED_FROM_REQUEST_COMMON = [
    "Connection",
    "Content-Length",
    "Content-MD5",
    "Expect",
    "Max-Forwards",
    "Proxy-Authenticate",
    "Server",
    "TE",
    "Transfer-Encoding",
    "Trailer",
    "Upgrade",
    "WWW-Authenticate",
]
DROPPED_FROM_REQUEST_COMMON_LOWER = [header.lower() for header in DROPPED_FROM_REQUEST_COMMON]

# These headers are part of the invocation request. However, they will not be part of the endpoint request.
# However, it happens before applying mapping templates, as overriding these will affect the requests.
DROPPED_FROM_REQUEST_PROXY_COMMON = ["Host", "Content-Encoding"]

# These are dropped after the templates override were applied. they will never make it to the requests.
DROPPED_FROM_INTEGRATION_REQUESTS_COMMON = ["Expect", "Proxy-Authenticate", "TE"]
DROPPED_FROM_INTEGRATION_REQUESTS_AWS = [*DROPPED_FROM_INTEGRATION_REQUESTS_COMMON, "Referer"]
DROPPED_FROM_INTEGRATION_REQUESTS_HTTP = [*DROPPED_FROM_INTEGRATION_REQUESTS_COMMON, "Via"]

# These are dropped after the templates override were applied. they will never make it to the requests.
DROPPED_FROM_INTEGRATION_RESPONSES_COMMON = ["Transfer-Encoding"]

DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY = [
    *DROPPED_FROM_INTEGRATION_RESPONSES_COMMON,
    "Content-Encoding",
    "Via",
]

# Illegal headers to attempt and remap.
ILLEGAL_INTEGRATION_REQUESTS_COMMON = [
    "content-length",
    "transfer-encoding",
    "x-amzn-trace-id",
    "X-Amzn-Apigateway-Api-Id",
]
ILLEGAL_INTEGRATION_REQUESTS_AWS = [
    *ILLEGAL_INTEGRATION_REQUESTS_COMMON,
    "authorization",
    "connection",
    "expect",
    "proxy-authenticate",
    "te",
]

# Headers that will receive a remap
REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON = [
    "Connection",
    "Content-Length",
    "Date",
    "Server",
]
REMAPPED_FROM_INTEGRATION_RESPONSE_NON_PROXY = [
    *REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON,
    "Authorization",
    "Content-MD5",
    "Expect",
    "Host",
    "Max-Forwards",
    "Proxy-Authenticate",
    "Trailer",
    "Upgrade",
    "User-Agent",
    "WWW-Authenticate",
]
# Default headers
DEFAULT_REQUEST_HEADERS = {"Accept": APPLICATION_JSON}
DEFAULT_RESPONSE_HEADERS = {"Content-Type": APPLICATION_JSON}


def should_drop_header_from_invocation(header: str) -> bool:
    """These headers are not making it to the invocation requests. Even Proxy integrations are not sending them."""
    return header.lower() in DROPPED_FROM_REQUEST_COMMON_LOWER


def build_multi_value_headers(headers: Headers) -> dict[str, list[str]]:
    multi_value_headers = defaultdict(list)
    for key, value in headers:
        multi_value_headers[key].append(value)

    return multi_value_headers


def _drop_headers(headers: Headers, to_drop: Iterable[str]):
    """Will modify the provided headers in-place. Dropping matching headers from the provided list"""
    for header in to_drop:
        if headers.get(header):
            LOG.debug("Dropping header: %s", header)
            headers.pop(header)


def drop_invocation_headers(headers: Headers, integration_type: IntegrationType):
    """Will modify the provided headers in-place. Dropping matching headers from the provided integration type"""
    _drop_headers(headers, DROPPED_FROM_REQUEST_PROXY_COMMON)


def drop_request_headers(headers: Headers, integration_type: IntegrationType):
    """Will modify the provided headers in-place. Dropping matching headers for the provided integration type"""
    match integration_type:
        case IntegrationType.AWS:
            _drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_AWS)
        case IntegrationType.HTTP | IntegrationType.HTTP_PROXY:
            _drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_HTTP)
        case _:
            _drop_headers(headers, DROPPED_FROM_INTEGRATION_REQUESTS_COMMON)


def drop_response_headers(headers: Headers, integration_type: IntegrationType):
    """Will modify the provided headers in-place. Dropping matching headers for the provided integration type"""
    match integration_type:
        case IntegrationType.HTTP_PROXY:
            _drop_headers(headers, DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY)
        case _:
            _drop_headers(headers, DROPPED_FROM_INTEGRATION_RESPONSES_COMMON)


def remap_response_headers(headers: Headers, integration_type: IntegrationType):
    """Remaps the provided headers in-place. Adding new `x-amzn-Remapped-` headers and dropping the original headers"""
    match integration_type:
        case IntegrationType.HTTP | IntegrationType.AWS:
            to_remap = REMAPPED_FROM_INTEGRATION_RESPONSE_NON_PROXY
        case _:
            to_remap = REMAPPED_FROM_INTEGRATION_RESPONSE_COMMON

    for header in to_remap:
        if headers.get(header):
            LOG.debug("Remapping header: %s", header)
            remapped = headers.pop(header)
            headers[f"x-amzn-Remapped-{header}"] = remapped


def validate_request_headers(headers: dict[str, str], integration_type: IntegrationType):
    """Validates and raises an error when attempting to set an illegal header"""
    to_validate = ILLEGAL_INTEGRATION_REQUESTS_COMMON
    match integration_type:
        case IntegrationType.AWS | IntegrationType.AWS_PROXY:
            to_validate = ILLEGAL_INTEGRATION_REQUESTS_AWS

    for header in headers.keys():
        if header.lower() in to_validate:
            LOG.debug(
                "Execution failed due to configuration error: %s header already present", header
            )
            raise InternalServerError("Internal server error")


def _set_default_headers(headers: Headers, default_headers: dict[str, str]):
    for header, value in default_headers.items():
        if not headers.get(header):
            headers.set(header, value)


def set_default_response_headers(
    headers: Headers,
    context: RestApiInvocationContext,
    integration_type: IntegrationType = None,
):
    """Utils to set the default apigw headers. Trace id isn't applied to HTTP_PROXY and Gateway Responses"""
    _set_default_headers(headers, DEFAULT_RESPONSE_HEADERS)
    headers.set("x-amzn-RequestId", context.context_variables["requestId"])
    # Todo, as we go into monitoring, we might want to have these values come from the context?
    headers.set("x-amz-apigw-id", short_uid() + "=")
    if integration_type and integration_type != IntegrationType.HTTP_PROXY:
        headers.set("X-Amzn-Trace-Id", short_uid())  # TODO


def set_default_request_headers(
    headers: Headers, integration_type: IntegrationType, context: RestApiInvocationContext
):
    _set_default_headers(
        headers, {**DEFAULT_REQUEST_HEADERS, "User-Agent": f"AmazonAPIGateway_{context.api_id}"}
    )
    headers.set("X-Amzn-Trace-Id", short_uid())  # TODO
    if integration_type not in (IntegrationType.AWS_PROXY, IntegrationType.AWS):
        headers.set("X-Amzn-Apigateway-Api-Id", context.api_id)
