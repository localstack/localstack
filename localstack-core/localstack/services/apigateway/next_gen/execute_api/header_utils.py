import logging
from collections import defaultdict
from typing import Iterable

from werkzeug.datastructures.headers import Headers

from localstack.aws.api.apigateway import IntegrationType
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
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

# These are dropped after the templates override were applied. they will never make it to the requests.
DROPPED_FROM_INTEGRATION_RESPONSES_COMMON = ["Transfer-Encoding"]

DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY = [
    *DROPPED_FROM_INTEGRATION_RESPONSES_COMMON,
    "Content-Encoding",
    "Via",
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


def should_drop_header_from_invocation(header: str) -> bool:
    """These headers are not making it to the invocation requests. Even Proxy integrations are not sending them."""
    return header.lower() in DROPPED_FROM_REQUEST_COMMON_LOWER


def build_multi_value_headers(headers: Headers) -> dict[str, list[str]]:
    multi_value_headers = defaultdict(list)
    for key, value in headers:
        multi_value_headers[key].append(value)

    return multi_value_headers


def drop_headers(headers: Headers, to_drop: Iterable[str]):
    """Will modify the provided headers in-place. Dropping matching headers from the provided list"""
    for header in to_drop:
        if headers.get(header):
            LOG.debug("Dropping header: %s", header)
            headers.remove(header)


def drop_response_headers(headers: Headers, integration_type: IntegrationType):
    """Will modify the provided headers in-place. Dropping matching headers for the provided integration type"""
    match integration_type:
        case IntegrationType.HTTP_PROXY:
            drop_headers(headers, DROPPED_FROM_INTEGRATION_RESPONSES_HTTP_PROXY)
        case _:
            drop_headers(headers, DROPPED_FROM_INTEGRATION_RESPONSES_COMMON)


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


def set_default_headers(headers: Headers, default_headers: dict[str, str]):
    for header, value in default_headers.items():
        if not headers.get(header):
            headers.set(header, value)


def set_default_response_headers(
    headers: Headers,
    context: RestApiInvocationContext,
    integration_type: IntegrationType = None,
):
    """Utils to set the default apigw headers. Trace id isn't applied to HTTP_PROXY and Gateway Responses"""
    headers.set("x-amzn-RequestId", context.context_variables["requestId"])
    # Todo, as we go into monitoring, we might want to have these values come from the context?
    headers.set("x-amz-apigw-id", short_uid() + "=")
    if integration_type and integration_type != IntegrationType.HTTP_PROXY:
        headers.set("X-Amzn-Trace-Id", short_uid())  # TODO
