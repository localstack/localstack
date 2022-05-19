"""
A set of handles which handle Cross Origin Resource Sharing (CORS).
"""
import logging
import re
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
from localstack.aws.protocol.service_router import determine_aws_service_name
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

LOG = logging.getLogger(__name__)


class CorsEnforcer(Handler):
    """
    Enforces Cross-Origin-Resource-Sharing (CORS).
    """

    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        if (
            not config.DISABLE_CORS_CHECKS
            and self.should_enforce_self_managed_service(context.request)
            and not self.is_cors_origin_allowed(context.request.headers)
        ):
            LOG.info(
                "Blocked CORS request from forbidden origin %s",
                context.request.headers.get("origin") or context.request.headers.get("referer"),
            )
            response.status_code = 403
            chain.terminate()

    @staticmethod
    def should_enforce_self_managed_service(request: Request):
        if config.DISABLE_CUSTOM_CORS_S3 and config.DISABLE_CUSTOM_CORS_APIGATEWAY:
            return True
        # allow only certain api calls without checking origin
        api = determine_aws_service_name(request)
        if not config.DISABLE_CUSTOM_CORS_S3 and api == "s3":
            return False
        if not config.DISABLE_CUSTOM_CORS_APIGATEWAY and api == "apigateway":
            return False
        return True

    @staticmethod
    def is_cors_origin_allowed(headers: Headers):
        """Returns true if origin is allowed to perform cors requests, false otherwise"""
        allowed_origins = ALLOWED_CORS_ORIGINS
        origin = headers.get("origin")
        referer = headers.get("referer")
        if origin:
            return CorsEnforcer._is_in_allowed_origins(allowed_origins, origin)
        elif referer:
            referer_uri = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(referer))
            return CorsEnforcer._is_in_allowed_origins(allowed_origins, referer_uri)
        # If both headers are not set, let it through (awscli etc. do not send these headers)
        return True

    @staticmethod
    def _is_in_allowed_origins(allowed_origins, origin):
        for allowed_origin in allowed_origins:
            if allowed_origin == "*" or origin == allowed_origin:
                return True
        return False


class CorsResponseEnricher(Handler):
    def __call__(self, chain: HandlerChain, context: RequestContext, response: Response):
        # use this config to disable returning CORS headers entirely (more restrictive security setting)
        if config.DISABLE_CORS_HEADERS:
            return
        request_headers = context.request.headers
        headers = response.headers

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

        for header in ALLOWED_CORS_RESPONSE_HEADERS:
            if headers.get(header) == "":
                del headers[header]
