"""
A set of handlers which handle Cross Origin Resource Sharing (CORS).
"""
import logging
import re
from typing import List, Set
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
from localstack.aws.api import RequestContext
from localstack.aws.chain import Handler, HandlerChain
from localstack.config import EXTRA_CORS_ALLOWED_HEADERS, EXTRA_CORS_EXPOSE_HEADERS
from localstack.constants import LOCALHOST, LOCALHOST_HOSTNAME, PATH_USER_REQUEST
from localstack.http import Response

LOG = logging.getLogger(__name__)

# header name constants
ACL_REQUEST_PRIVATE_NETWORK = "Access-Control-Request-Private-Network"
ACL_ALLOW_PRIVATE_NETWORK = "Access-Control-Allow-Private-Network"

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


def _get_allowed_cors_internal_domains() -> Set[str]:
    """
    Construct the list of allowed internal domains for CORS enforcement purposes
    Defined as function to allow easier testing with monkeypatch of config values
    """
    return {LOCALHOST, LOCALHOST_HOSTNAME, config.HOSTNAME_EXTERNAL}


_ALLOWED_INTERNAL_DOMAINS = _get_allowed_cors_internal_domains()


def _get_allowed_cors_ports() -> Set[int]:
    """
    Construct the list of allowed ports for CORS enforcement purposes
    Defined as function to allow easier testing with monkeypatch of config values
    """
    return set([config.EDGE_PORT] + ([config.EDGE_PORT_HTTP] if config.EDGE_PORT_HTTP else []))


_ALLOWED_INTERNAL_PORTS = _get_allowed_cors_ports()


def _get_allowed_cors_origins() -> List[str]:
    """Construct the list of allowed origins for CORS enforcement purposes"""
    result = [
        # allow access from Web app and localhost domains
        "https://app.localstack.cloud",
        "http://app.localstack.cloud",
        "https://localhost",
        "https://localhost.localstack.cloud",
        # for requests from Electron apps, e.g., DynamoDB NoSQL Workbench
        "file://",
    ]
    # Add allowed origins for localhost domains, using different protocol/port combinations.
    # If a different port is configured for EDGE_PORT_HTTP, add it to allowed origins as well
    for protocol in {"http", "https"}:
        for port in _get_allowed_cors_ports():
            result.append(f"{protocol}://{LOCALHOST}:{port}")
            result.append(f"{protocol}://{LOCALHOST_HOSTNAME}:{port}")

    if config.EXTRA_CORS_ALLOWED_ORIGINS:
        origins = config.EXTRA_CORS_ALLOWED_ORIGINS.split(",")
        origins = [origin.strip() for origin in origins]
        origins = [origin for origin in origins if origin != ""]
        result += origins

    return result


# allowed origins used for CORS / CSRF checks
ALLOWED_CORS_ORIGINS = _get_allowed_cors_origins()

# allowed dynamic internal origin
# must follow the same pattern with 3 matching group, group 2 being the domain and group 3 the port
# TODO: might need to match/group the scheme also?
DYNAMIC_INTERNAL_ORIGINS = (
    re.compile("(.*)\\.s3-website\\.(.[^:]*)(:[0-9]{2,5})?"),
    re.compile("(.*)\\.cloudfront\\.(.[^:]*)(:[0-9]{2,5})?"),
)


def should_enforce_self_managed_service(context: RequestContext) -> bool:
    """
    Some services are handling their CORS checks on their own (depending on config vars).

    :param context: context of the request for which to check if the CORS checks should be executed in here or in
                    the targeting service
    :return: True if the CORS rules should be enforced in here.
    """
    if config.DISABLE_CUSTOM_CORS_S3 and config.DISABLE_CUSTOM_CORS_APIGATEWAY:
        return True
    # allow only certain api calls without checking origin
    if context.service:
        service_name = context.service.service_name
        if not config.DISABLE_CUSTOM_CORS_S3 and service_name == "s3":
            return False
        if not config.DISABLE_CUSTOM_CORS_APIGATEWAY and service_name == "apigateway":
            is_user_request = (
                PATH_USER_REQUEST in context.request.path or ".execute-api." in context.request.host
            )
            if is_user_request:
                return False
    return True


class CorsEnforcer(Handler):
    """
    Handler which enforces Cross-Origin-Resource-Sharing (CORS) rules.
    This handler needs to be at the top of the handler chain to ensure that these security rules are enforced before any
    commands are executed.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response) -> None:
        if not should_enforce_self_managed_service(context):
            return
        if not config.DISABLE_CORS_CHECKS and not self.is_cors_origin_allowed(
            context.request.headers
        ):
            LOG.info(
                "Blocked CORS request from forbidden origin %s",
                context.request.headers.get("origin") or context.request.headers.get("referer"),
            )
            response.status_code = 403
            chain.terminate()
        elif context.request.method == "OPTIONS" and not config.DISABLE_PREFLIGHT_PROCESSING:
            # we want to return immediately here, but we do not want to omit our response chain for cors headers
            response.status_code = 204
            chain.stop()

    @staticmethod
    def is_cors_origin_allowed(headers: Headers) -> bool:
        """Returns true if origin is allowed to perform cors requests, false otherwise."""
        origin = headers.get("origin")
        referer = headers.get("referer")
        if origin:
            return CorsEnforcer._is_in_allowed_origins(ALLOWED_CORS_ORIGINS, origin)
        elif referer:
            referer_uri = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(referer))
            return CorsEnforcer._is_in_allowed_origins(ALLOWED_CORS_ORIGINS, referer_uri)
        # If both headers are not set, let it through (awscli etc. do not send these headers)
        return True

    @staticmethod
    def _is_in_allowed_origins(allowed_origins: List[str], origin: str) -> bool:
        """Returns true if the `origin` is in the `allowed_origins`."""
        for allowed_origin in allowed_origins:
            if allowed_origin == "*" or origin == allowed_origin:
                return True

        # performance wise, this is not very heavy because most of the regular requests will match above
        # this would be executed mostly when rejecting or actually using content served by CloudFront or S3 website
        for dynamic_origin in DYNAMIC_INTERNAL_ORIGINS:
            match = dynamic_origin.match(origin)
            if (
                match
                and (match.group(2) in _ALLOWED_INTERNAL_DOMAINS)
                and (not (port := match.group(3)) or int(port[1:]) in _ALLOWED_INTERNAL_PORTS)
            ):
                return True

        return False


class CorsResponseEnricher(Handler):
    """
    ResponseHandler which adds Cross-Origin-Request-Sharing (CORS) headers (Access-Control-*) to the response.
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        headers = response.headers
        # Remove empty CORS headers
        for header in ALLOWED_CORS_RESPONSE_HEADERS:
            if headers.get(header) == "":
                del headers[header]

        # use DISABLE_CORS_HEADERS to disable returning CORS headers entirely (more restrictive security setting)
        # also don't add CORS response headers if the service manages the CORS handling
        if config.DISABLE_CORS_HEADERS or not should_enforce_self_managed_service(context):
            return

        request_headers = context.request.headers
        self.add_cors_headers(request_headers, response_headers=headers)

    @staticmethod
    def add_cors_headers(request_headers: Headers, response_headers: Headers):
        if ACL_ORIGIN not in response_headers:
            response_headers[ACL_ORIGIN] = (
                request_headers["origin"]
                if request_headers.get("origin") and not config.DISABLE_CORS_CHECKS
                else "*"
            )
        if ACL_METHODS not in response_headers:
            response_headers[ACL_METHODS] = ",".join(CORS_ALLOWED_METHODS)
        if ACL_ALLOW_HEADERS not in response_headers:
            requested_headers = response_headers.get(ACL_REQUEST_HEADERS, "")
            requested_headers = re.split(r"[,\s]+", requested_headers) + CORS_ALLOWED_HEADERS
            response_headers[ACL_ALLOW_HEADERS] = ",".join([h for h in requested_headers if h])
        if ACL_EXPOSE_HEADERS not in response_headers:
            response_headers[ACL_EXPOSE_HEADERS] = ",".join(CORS_EXPOSE_HEADERS)
        if (
            request_headers.get(ACL_REQUEST_PRIVATE_NETWORK) == "true"
            and ACL_ALLOW_PRIVATE_NETWORK not in response_headers
        ):
            response_headers[ACL_ALLOW_PRIVATE_NETWORK] = "true"
