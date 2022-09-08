import logging
import re
from typing import List, Optional
from urllib.parse import urlparse

from flask_cors.core import (
    ACL_ALLOW_HEADERS,
    ACL_EXPOSE_HEADERS,
    ACL_METHODS,
    ACL_ORIGIN,
    ACL_REQUEST_HEADERS,
)
from werkzeug.datastructures import Headers

from localstack import config
from localstack.config import (
    EXTRA_CORS_ALLOWED_HEADERS,
    EXTRA_CORS_ALLOWED_ORIGINS,
    EXTRA_CORS_EXPOSE_HEADERS,
)
from localstack.http import Request, Response

# CORS constants below
CORS_ALLOWED_HEADERS = [
    "authorization",
    "cache-control",
    "content-length",
    "content-md5",
    "content-type",
    "etag",
    "location",
    "x-amz-acl",
    "x-amz-content-sha256",
    "x-amz-date",
    "x-amz-request-id",
    "x-amz-security-token",
    "x-amz-tagging",
    "x-amz-target",
    "x-amz-user-agent",
    "x-amz-version-id",
    "x-amzn-requestid",
    "x-localstack-target",
    # for AWS SDK v3
    "amz-sdk-invocation-id",
    "amz-sdk-request",
]
if EXTRA_CORS_ALLOWED_HEADERS:
    CORS_ALLOWED_HEADERS += EXTRA_CORS_ALLOWED_HEADERS.split(",")

CORS_ALLOWED_METHODS = ("HEAD", "GET", "PUT", "POST", "DELETE", "OPTIONS", "PATCH")

CORS_EXPOSE_HEADERS = (
    "etag",
    "x-amz-version-id",
)
if EXTRA_CORS_EXPOSE_HEADERS:
    CORS_EXPOSE_HEADERS += tuple(EXTRA_CORS_EXPOSE_HEADERS.split(","))

ALLOWED_CORS_RESPONSE_HEADERS = [
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
]

ALLOWED_CORS_ORIGINS = [
    "https://app.localstack.cloud",
    "http://app.localstack.cloud",
    f"https://localhost:{config.EDGE_PORT}",
    f"http://localhost:{config.EDGE_PORT}",
    f"https://localhost.localstack.cloud:{config.EDGE_PORT}",
    f"http://localhost.localstack.cloud:{config.EDGE_PORT}",
    "https://localhost",
    "https://localhost.localstack.cloud",
    # for requests from Electron apps, e.g., DynamoDB NoSQL Workbench
    "file://",
]
if EXTRA_CORS_ALLOWED_ORIGINS:
    ALLOWED_CORS_ORIGINS += EXTRA_CORS_ALLOWED_ORIGINS.split(",")

ACL_REQUEST_PRIVATE_NETWORK = "Access-Control-Request-Private-Network"
ACL_ALLOW_PRIVATE_NETWORK = "Access-Control-Allow-Private-Network"


LOG = logging.getLogger(__name__)


def enforce_cors_on_request(
    request: Request, response: Optional[Response] = Response()
) -> Optional[Response]:
    if not config.DISABLE_CORS_CHECKS and not is_cors_origin_allowed(request.headers):
        LOG.info(
            "Blocked CORS request from forbidden origin %s",
            request.headers.get("origin") or request.headers.get("referer"),
        )
        response.status_code = 403
        # TODO the chain should _terminate_ here!
        return response
    elif request.method == "OPTIONS" and not config.DISABLE_PREFLIGHT_PROCESSING:
        # we want to return immediately here, but we do not want to omit our response chain for cors headers
        response.status_code = 204
        # TODO the chain should _terminate_ here!
        return response


def is_cors_origin_allowed(headers: Headers) -> bool:
    """Returns true if origin is allowed to perform cors requests, false otherwise."""
    origin = headers.get("origin")
    referer = headers.get("referer")
    if origin:
        return _is_in_allowed_origins(ALLOWED_CORS_ORIGINS, origin)
    elif referer:
        referer_uri = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(referer))
        return _is_in_allowed_origins(ALLOWED_CORS_ORIGINS, referer_uri)
    # If both headers are not set, let it through (awscli etc. do not send these headers)
    return True


def _is_in_allowed_origins(allowed_origins: List[str], origin: str) -> bool:
    """Returns true if the `origin` is in the `allowed_origins`."""
    for allowed_origin in allowed_origins:
        if allowed_origin == "*" or origin == allowed_origin:
            return True
    return False


def enrich_cors_response_headers(request: Request, response: Response):
    headers = response.headers
    # Remove empty CORS headers
    for header in ALLOWED_CORS_RESPONSE_HEADERS:
        if headers.get(header) == "":
            del headers[header]

    # use DISABLE_CORS_HEADERS to disable returning CORS headers entirely (more restrictive security setting)
    if config.DISABLE_CORS_HEADERS:
        return

    request_headers = request.headers
    if ACL_ORIGIN not in headers:
        headers[ACL_ORIGIN] = (
            request_headers["origin"]
            if request_headers.get("origin") and not config.DISABLE_CORS_CHECKS
            else "*"
        )
    if ACL_METHODS not in headers:
        headers[ACL_METHODS] = ",".join(CORS_ALLOWED_METHODS)
    if ACL_ALLOW_HEADERS not in headers:
        requested_headers = headers.get(ACL_REQUEST_HEADERS, "")
        requested_headers = re.split(r"[,\s]+", requested_headers) + CORS_ALLOWED_HEADERS
        headers[ACL_ALLOW_HEADERS] = ",".join([h for h in requested_headers if h])
    if ACL_EXPOSE_HEADERS not in headers:
        headers[ACL_EXPOSE_HEADERS] = ",".join(CORS_EXPOSE_HEADERS)
    if (
        request_headers.get(ACL_REQUEST_PRIVATE_NETWORK) == "true"
        and ACL_ALLOW_PRIVATE_NETWORK not in headers
    ):
        headers[ACL_ALLOW_PRIVATE_NETWORK] = "true"
