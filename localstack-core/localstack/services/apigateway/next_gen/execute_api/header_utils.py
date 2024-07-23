import logging
from collections import defaultdict
from typing import Iterable

from werkzeug.datastructures.headers import Headers

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
    dropped_headers = []

    for header in to_drop:
        if headers.get(header):
            headers.remove(header)
            dropped_headers.append(header)

    LOG.debug("Dropping headers: %s", dropped_headers)


def set_default_headers(headers: Headers, default_headers: dict[str, str]):
    for header, value in default_headers.items():
        if not headers.get(header):
            headers.set(header, value)
