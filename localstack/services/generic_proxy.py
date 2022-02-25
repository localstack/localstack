import functools
import json
import logging
import os
import re
import socket
import ssl
import threading
from asyncio.selector_events import BaseSelectorEventLoop
from typing import Dict, List, Match, Optional, Union
from urllib.parse import parse_qs, unquote, urlencode, urlparse

import requests
from flask_cors import CORS
from flask_cors.core import (
    ACL_ALLOW_HEADERS,
    ACL_EXPOSE_HEADERS,
    ACL_METHODS,
    ACL_ORIGIN,
    ACL_REQUEST_HEADERS,
)
from requests.models import Request, Response
from werkzeug.exceptions import HTTPException

from localstack import config
from localstack.config import (
    EXTRA_CORS_ALLOWED_HEADERS,
    EXTRA_CORS_ALLOWED_ORIGINS,
    EXTRA_CORS_EXPOSE_HEADERS,
)
from localstack.constants import (
    APPLICATION_JSON,
    AWS_REGION_US_EAST_1,
    BIND_HOST,
    HEADER_LOCALSTACK_REQUEST_URL,
)
from localstack.services.messages import Headers, MessagePayload
from localstack.services.messages import Request as RoutingRequest
from localstack.services.messages import Response as RoutingResponse
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import LambdaResponse
from localstack.utils.aws.aws_stack import is_internal_call_context
from localstack.utils.aws.request_context import RequestContextManager, get_proxy_request_for_thread
from localstack.utils.common import (
    empty_context_manager,
    generate_ssl_cert,
    json_safe,
    path_from_url,
    start_thread,
    to_bytes,
    to_str,
    wait_for_port_open,
)
from localstack.utils.server import http2_server
from localstack.utils.serving import Server

# set up logger
LOG = logging.getLogger(__name__)

# path for test certificate
SERVER_CERT_PEM_FILE = "server.test.pem"

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
]
if EXTRA_CORS_ALLOWED_ORIGINS:
    ALLOWED_CORS_ORIGINS += EXTRA_CORS_ALLOWED_ORIGINS.split(",")


class ProxyListener(object):
    # List of `ProxyListener` instances that are enabled by default for all requests.
    # For inbound flows, the default listeners are applied *before* forwarding requests
    # to the backend; for outbound flows, the default listeners are applied *after* the
    # response has been received from the backend service.
    DEFAULT_LISTENERS = []

    def forward_request(
        self, method: str, path: str, data: MessagePayload, headers: Headers
    ) -> Union[int, Response, Request, dict, bool]:
        """This interceptor method is called by the proxy when receiving a new request
        (*before* forwarding the request to the backend service). It receives details
        of the incoming request, and returns either of the following results:

        * True if the request should be forwarded to the backend service as-is (default).
        * An integer (e.g., 200) status code to return directly to the client without
          calling the backend service.
        * An instance of requests.models.Response to return directly to the client without
          calling the backend service.
        * An instance of requests.models.Request which represents a new/modified request
          that will be forwarded to the backend service.
        * Any other value, in which case a 503 Bad Gateway is returned to the client
          without calling the backend service.
        """
        return True

    def return_response(
        self,
        method: str,
        path: str,
        data: MessagePayload,
        headers: Headers,
        response: Response,
    ) -> Optional[Response]:
        """This interceptor method is called by the proxy when returning a response
        (*after* having forwarded the request and received a response from the backend
        service). It receives details of the incoming request as well as the response
        from the backend service, and returns either of the following results:

        * An instance of requests.models.Response to return to the client instead of the
          actual response returned from the backend service.
        * Any other value, in which case the response from the backend service is
          returned to the client.
        """
        return None

    def get_forward_url(self, method: str, path: str, data, headers):
        """Return a custom URL to forward the given request to. If a falsy value is returned,
        then the default URL will be used.
        """
        return None


class MessageModifyingProxyListener(ProxyListener):
    # Special handler that can be used to modify an inbound/outbound message
    # and forward it to the next handler in the chain (instead of forwarding
    # to the backend directly, which is the default for regular ProxyListeners)
    # TODO: to be replaced with listener chain in ASF Gateway, once integrated

    def forward_request(
        self, method: str, path: str, data: MessagePayload, headers: Headers
    ) -> Optional[RoutingRequest]:
        """Return a RoutingRequest with modified request data, or None to forward the request
        unmodified"""
        return None

    def return_response(
        self,
        method: str,
        path: str,
        data: MessagePayload,
        headers: Headers,
        response: Response,
    ) -> Optional[RoutingResponse]:
        """Return a RoutingResponse with modified response data, or None to forward the response
        unmodified"""
        return None


class ArnPartitionRewriteListener(MessageModifyingProxyListener):
    """
    Intercepts requests and responses and tries to adjust the partitions in ARNs within the
    intercepted requests.
    For incoming requests, the default partition is set ("aws").
    For outgoing responses, the partition is adjusted based on the region in the ARN, or by the
    default region
    if the ARN does not contain a region.
    This listener is used to support other partitions than the default "aws" partition (f.e.
    aws-us-gov) without
    rewriting all the cases where the ARN is parsed or constructed within LocalStack or moto.
    In other words, this listener makes sure that internally the ARNs are always in the partition
    "aws", while the
    client gets ARNs with the proper partition.
    """

    # Partition which should be statically set for incoming requests
    DEFAULT_INBOUND_PARTITION = "aws"

    class InvalidRegionException(Exception):
        """An exception indicating that a region could not be matched to a partition."""

        pass

    arn_regex = re.compile(
        r"arn:"  # Prefix
        r"(?P<Partition>(aws|aws-cn|aws-iso|aws-iso-b|aws-us-gov)*):"  # Partition
        r"(?P<Service>[\w-]*):"  # Service (lambda, s3, ecs,...)
        r"(?P<Region>[\w-]*):"  # Region (us-east-1, us-gov-west-1,...)
        r"(?P<AccountID>[\w-]*):"  # AccountID
        r"(?P<ResourcePath>"  # Combine the resource type and id to the ResourcePath
        r"((?P<ResourceType>[\w-]*)[:/])?"  # ResourceType (optional, f.e. S3 bucket name)
        r"(?P<ResourceID>[\w\-/*]*)"  # Resource ID (f.e. file name in S3)
        r")"
    )

    def forward_request(
        self, method: str, path: str, data: MessagePayload, headers: Headers
    ) -> Optional[RoutingRequest]:
        return RoutingRequest(
            method=method,
            path=self._adjust_partition_in_path(path, self.DEFAULT_INBOUND_PARTITION),
            data=self._adjust_partition(data, self.DEFAULT_INBOUND_PARTITION),
            headers=self._adjust_partition(headers, self.DEFAULT_INBOUND_PARTITION),
        )

    def return_response(
        self,
        method: str,
        path: str,
        data: MessagePayload,
        headers: Headers,
        response: Response,
    ) -> Optional[RoutingResponse]:
        # Only handle responses for calls from external clients
        if is_internal_call_context(headers):
            return None
        return RoutingResponse(
            status_code=response.status_code,
            content=self._adjust_partition(response.content),
            headers=self._adjust_partition(response.headers),
        )

    def _adjust_partition_in_path(self, path: str, static_partition: str = None):
        """Adjusts the (still url encoded) URL path"""
        parsed_url = urlparse(path)
        # Make sure to keep blank values, otherwise we drop query params which do not have a
        # value (f.e. "/?policy")
        decoded_query = parse_qs(qs=parsed_url.query, keep_blank_values=True)
        adjusted_path = self._adjust_partition(parsed_url.path, static_partition)
        adjusted_query = self._adjust_partition(decoded_query, static_partition)
        encoded_query = urlencode(adjusted_query, doseq=True)

        # Make sure to avoid empty equals signs (in between and in the end)
        encoded_query = encoded_query.replace("=&", "&")
        encoded_query = re.sub(r"=$", "", encoded_query)

        return f"{adjusted_path}{('?' + encoded_query) if encoded_query else ''}"

    def _adjust_partition(self, source, static_partition: str = None):
        # Call this function recursively if we get a dictionary or a list
        if isinstance(source, dict):
            result = {}
            for k, v in source.items():
                result[k] = self._adjust_partition(v, static_partition)
            return result
        if isinstance(source, list):
            result = []
            for v in source:
                result.append(self._adjust_partition(v, static_partition))
            return result
        elif isinstance(source, bytes):
            try:
                decoded = unquote(to_str(source))
                adjusted = self._adjust_partition(decoded, static_partition)
                return to_bytes(adjusted)
            except UnicodeDecodeError:
                # If the body can't be decoded to a string, we return the initial source
                return source
        elif not isinstance(source, str):
            # Ignore any other types
            return source
        return self.arn_regex.sub(lambda m: self._adjust_match(m, static_partition), source)

    def _adjust_match(self, match: Match, static_partition: str = None):
        region = match.group("Region")
        partition = self._partition_lookup(region) if static_partition is None else static_partition
        service = match.group("Service")
        account_id = match.group("AccountID")
        resource_path = match.group("ResourcePath")
        return f"arn:{partition}:{service}:{region}:{account_id}:{resource_path}"

    def _partition_lookup(self, region: str):
        try:
            partition = self._get_partition_for_region(region)
        except ArnPartitionRewriteListener.InvalidRegionException:
            try:
                # If the region is not properly set (f.e. because it is set to a wildcard),
                # the partition is determined based on the default region.
                partition = self._get_partition_for_region(config.DEFAULT_REGION)
            except self.InvalidRegionException:
                # If it also fails with the DEFAULT_REGION, we use us-east-1 as a fallback
                partition = self._get_partition_for_region(AWS_REGION_US_EAST_1)
        return partition

    def _get_partition_for_region(self, region: str) -> str:
        # Region-Partition matching is based on the "regionRegex" definitions in the endpoints.json
        # in the botocore package.
        if region.startswith("us-gov-"):
            return "aws-us-gov"
        elif region.startswith("us-iso-"):
            return "aws-iso"
        elif region.startswith("us-isob-"):
            return "aws-iso-b"
        elif region.startswith("cn-"):
            return "aws-cn"
        elif re.match(r"^(us|eu|ap|sa|ca|me|af)-\w+-\d+$", region):
            return "aws"
        else:
            raise ArnPartitionRewriteListener.InvalidRegionException(
                f"Region ({region}) could not be matched to a partition."
            )


# -------------------
# BASE BACKEND UTILS
# -------------------


class RegionBackend(object):
    """Base class for region-specific backends for the different APIs.
    RegionBackend lookup methods are not thread safe."""

    REGIONS: Dict[str, "RegionBackend"]

    name: str  # name of the region

    @classmethod
    def get(cls, region: str = None) -> "RegionBackend":
        region = region or cls.get_current_request_region()

        regions = cls.regions()
        backend = regions.get(region)
        if not backend:
            backend = cls()
            backend.name = region
            regions[region] = backend

        return regions[region]

    @classmethod
    def regions(cls) -> Dict[str, "RegionBackend"]:
        if not hasattr(cls, "REGIONS"):
            # maps region name to region backend instance
            cls.REGIONS = {}
        return cls.REGIONS

    @classmethod
    def get_current_request_region(cls):
        return aws_stack.get_region()

    @classmethod
    def reset(cls):
        """Reset the (in-memory) state of this service region backend."""
        # for now, simply reset the regions and discard all existing region instances
        cls.REGIONS = {}
        return cls.regions()


# ---------------------
# PROXY LISTENER UTILS
# ---------------------


def append_cors_headers(request_headers=None, response=None):
    # Note: Use "response is not None" here instead of "not response"!
    headers = {} if response is None else response.headers

    # In case we have LambdaResponse copy multivalue headers to regular headers, since
    # CaseInsensitiveDict does not support "__contains__" and it's easier to deal with
    # a single headers object
    if isinstance(response, LambdaResponse):
        for key in response.multi_value_headers.keys():
            headers_list = list(response.multi_value_headers[key]) + [response.headers.get(key)]
            headers_list = [str(h) for h in headers_list if h is not None]
            headers[key] = ",".join(headers_list)
        response.multi_value_headers = {}

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


def http_exception_to_response(e: HTTPException):
    """Convert a werkzeug HTTP exception to a requests.Response object"""
    response = Response()
    response.status_code = e.code
    response.headers.update(dict(e.get_headers()))
    body = e.get_body()
    response.headers["Content-Length"] = str(len(str(body or "")))
    response._content = body
    return response


def cors_error_response():
    response = Response()
    response.status_code = 403
    return response


def _is_in_allowed_origins(allowed_origins, origin):
    for allowed_origin in allowed_origins:
        if allowed_origin == "*" or origin == allowed_origin:
            return True
    return False


def is_cors_origin_allowed(headers, allowed_origins=None):
    """Returns true if origin is allowed to perform cors requests, false otherwise"""
    allowed_origins = ALLOWED_CORS_ORIGINS if allowed_origins is None else allowed_origins
    origin = headers.get("origin")
    referer = headers.get("referer")
    if origin:
        return _is_in_allowed_origins(allowed_origins, origin)
    elif referer:
        referer_uri = "{uri.scheme}://{uri.netloc}".format(uri=urlparse(referer))
        return _is_in_allowed_origins(allowed_origins, referer_uri)
    # If both headers are not set, let it through (awscli etc. do not send these headers)
    return True


def should_enforce_self_managed_service(method, path, headers, data):
    if config.DISABLE_CUSTOM_CORS_S3 and config.DISABLE_CUSTOM_CORS_APIGATEWAY:
        return True
    # allow only certain api calls without checking origin
    import localstack.services.edge

    api, _ = localstack.services.edge.get_api_from_custom_rules(method, path, data, headers) or (
        "",
        None,
    )
    if not config.DISABLE_CUSTOM_CORS_S3 and api == "s3":
        return False
    if not config.DISABLE_CUSTOM_CORS_APIGATEWAY and api == "apigateway":
        return False
    return True


def update_path_in_url(base_url: str, path: str) -> str:
    """Construct a URL from the given base URL and path"""
    parsed = urlparse(base_url)
    path = path or ""
    path = path if path.startswith("/") else f"/{path}"
    protocol = f"{parsed.scheme}:" if parsed.scheme else ""
    return f"{protocol}//{parsed.netloc}{path}"


def with_context():
    """
    Decorator wraps function in a request context manager
    :return:
    """

    def context_manager(method=None, path=None, data_bytes=None, headers=None, *args, **kwargs):
        req_context = get_proxy_request_for_thread()
        ctx_manager = empty_context_manager()
        if not req_context:
            req_context = Request(url=path, data=data_bytes, headers=headers, method=method)
            ctx_manager = RequestContextManager(req_context)
        return ctx_manager

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            ctx_manager = context_manager(*args, **kwargs)
            with ctx_manager:
                value = func(*args, **kwargs)
            return value

        return wrapper

    return decorator


@with_context()
def modify_and_forward(
    method: str = None,
    path: str = None,
    data_bytes: bytes = None,
    headers: Headers = None,
    forward_base_url: str = None,
    listeners: List[ProxyListener] = None,
    client_address: str = None,
    server_address: str = None,
):
    """This is the central function that coordinates the incoming/outgoing messages
    with the proxy listeners (message interceptors)."""
    from localstack.services.edge import ProxyListenerEdge

    # Check origin / referer header before anything else happens.
    if (
        not config.DISABLE_CORS_CHECKS
        and should_enforce_self_managed_service(method, path, headers, data_bytes)
        and not is_cors_origin_allowed(headers)
    ):
        LOG.info(
            "Blocked CORS request from forbidden origin %s",
            headers.get("origin") or headers.get("referer"),
        )
        return cors_error_response()

    listeners = [lis for lis in listeners or [] if lis]
    default_listeners = list(ProxyListener.DEFAULT_LISTENERS)
    # ensure that MessageModifyingProxyListeners are not applied in the edge proxy request chain
    # TODO: find a better approach for this!
    is_edge_request = [lis for lis in listeners if isinstance(lis, ProxyListenerEdge)]
    if is_edge_request:
        default_listeners = [
            lis for lis in default_listeners if not isinstance(lis, MessageModifyingProxyListener)
        ]

    listeners_inbound = default_listeners + listeners
    listeners_outbound = listeners + default_listeners
    data = data_bytes
    original_request = RoutingRequest(method=method, path=path, data=data, headers=headers)

    def is_full_url(url):
        return re.match(r"[a-zA-Z]+://.+", url)

    def get_proxy_backend_url(_path, original_url=None, run_listeners=False):
        if is_full_url(_path):
            _path = _path.split("://", 1)[1]
            _path = "/%s" % (_path.split("/", 1)[1] if "/" in _path else "")
        base_url = forward_base_url or original_url
        result = update_path_in_url(base_url, _path)
        if run_listeners:
            for listener in listeners_inbound:
                result = listener.get_forward_url(method, path, data, headers) or result
        return result

    target_url = path
    if not is_full_url(target_url):
        target_url = "%s%s" % (forward_base_url, target_url)

    # update original "Host" header (moto s3 relies on this behavior)
    if not headers.get("Host"):
        headers["host"] = urlparse(target_url).netloc
    headers["X-Forwarded-For"] = build_x_forwarded_for(headers, client_address, server_address)

    response = None
    handler_chain_request = original_request.copy()
    modified_request_to_backend = None

    # run inbound handlers (pre-invocation)
    for listener in listeners_inbound:
        try:
            listener_result = listener.forward_request(
                method=handler_chain_request.method,
                path=handler_chain_request.path,
                data=handler_chain_request.data,
                headers=handler_chain_request.headers,
            )
        except HTTPException as e:
            # TODO: implement properly using exception handlers
            return http_exception_to_response(e)

        if isinstance(listener, MessageModifyingProxyListener):
            if isinstance(listener_result, RoutingRequest):
                # update the modified request details, then call next listener
                handler_chain_request.method = (
                    listener_result.method or handler_chain_request.method
                )
                handler_chain_request.path = listener_result.path or handler_chain_request.path
                if listener_result.data is not None:
                    handler_chain_request.data = listener_result.data
                if listener_result.headers is not None:
                    handler_chain_request.headers = listener_result.headers
            continue
        if isinstance(listener_result, Response):
            response = listener_result
            break
        if isinstance(listener_result, LambdaResponse):
            response = listener_result
            break
        if isinstance(listener_result, dict):
            response = Response()
            response._content = json.dumps(json_safe(listener_result))
            response.headers["Content-Type"] = APPLICATION_JSON
            response.status_code = 200
            break
        elif isinstance(listener_result, Request):
            # TODO: unify modified_request_to_backend (requests.Request) and
            #  handler_chain_request (ls.routing.Request)
            modified_request_to_backend = listener_result
            break
        elif http2_server.get_async_generator_result(listener_result):
            return listener_result
        elif listener_result is not True:
            # get status code from response, or use Bad Gateway status code
            code = listener_result if isinstance(listener_result, int) else 503
            response = Response()
            response.status_code = code
            response._content = ""
            response.headers["Content-Length"] = "0"
            append_cors_headers(request_headers=headers, response=response)
            return response

    # perform the actual invocation of the backend service
    headers_to_send = None
    data_to_send = None
    method_to_send = None
    if response is None:
        headers_to_send = handler_chain_request.headers
        headers_to_send["Connection"] = headers_to_send.get("Connection") or "close"
        data_to_send = handler_chain_request.data
        method_to_send = handler_chain_request.method
        request_url = get_proxy_backend_url(handler_chain_request.path, run_listeners=True)
        if modified_request_to_backend:
            if modified_request_to_backend.url:
                request_url = get_proxy_backend_url(
                    modified_request_to_backend.url, original_url=request_url
                )
            data_to_send = modified_request_to_backend.data
            if modified_request_to_backend.method:
                method_to_send = modified_request_to_backend.method

        # make sure we drop "chunked" transfer encoding from the headers to be forwarded
        headers_to_send.pop("Transfer-Encoding", None)
        response = requests.request(
            method_to_send,
            request_url,
            data=data_to_send,
            headers=headers_to_send,
            stream=True,
            verify=False,
        )

    # prevent requests from processing response body (e.g., to pass-through gzip encoded content
    # unmodified)
    pass_raw = (
        hasattr(response, "_content_consumed") and not response._content_consumed
    ) or response.headers.get("content-encoding") in ["gzip"]
    if pass_raw and getattr(response, "raw", None):
        new_content = response.raw.read()
        if new_content:
            response._content = new_content

    # run outbound handlers (post-invocation)
    for listener in listeners_outbound:
        updated_response = listener.return_response(
            method=method_to_send or handler_chain_request.method,
            path=handler_chain_request.path,
            data=data_to_send or handler_chain_request.data,
            headers=headers_to_send or handler_chain_request.headers,
            response=response,
        )
        message_modifier = isinstance(listener, MessageModifyingProxyListener)
        if message_modifier and isinstance(updated_response, RoutingResponse):
            # update the fields from updated_response in final response
            response.status_code = updated_response.status_code or response.status_code
            response.headers = updated_response.headers or response.headers
            if isinstance(updated_response.content, (str, bytes)):
                response._content = updated_response.content
        if isinstance(updated_response, Response):
            response = updated_response

    # allow pre-flight CORS headers by default
    from localstack.services.s3.s3_listener import ProxyListenerS3

    is_s3_listener = any(
        isinstance(service_listener, ProxyListenerS3) for service_listener in listeners
    )
    if not is_s3_listener:
        append_cors_headers(request_headers=headers, response=response)

    return response


def build_x_forwarded_for(headers, client_address, server_address):
    x_forwarded_for = headers.get("X-Forwarded-For")

    if x_forwarded_for:
        x_forwarded_for_list = (x_forwarded_for, client_address, server_address)
    else:
        x_forwarded_for_list = (client_address, server_address)

    return ", ".join(x_forwarded_for_list)


class DuplexSocket(ssl.SSLSocket):
    """Simple duplex socket wrapper that allows serving HTTP/HTTPS over the same port."""

    def accept(self):
        newsock, addr = socket.socket.accept(self)
        if DuplexSocket.is_ssl_socket(newsock) is not False:
            newsock = self.context.wrap_socket(
                newsock,
                do_handshake_on_connect=self.do_handshake_on_connect,
                suppress_ragged_eofs=self.suppress_ragged_eofs,
                server_side=True,
            )

        return newsock, addr

    @staticmethod
    def is_ssl_socket(newsock):
        """Returns True/False if the socket uses SSL or not, or None if the status cannot be
        determined"""

        def peek_ssl_header():
            peek_bytes = 5
            first_bytes = newsock.recv(peek_bytes, socket.MSG_PEEK)
            if len(first_bytes or "") != peek_bytes:
                return
            first_byte = first_bytes[0]
            return first_byte < 32 or first_byte >= 127

        try:
            return peek_ssl_header()
        except Exception:
            # Fix for "[Errno 11] Resource temporarily unavailable" - This can
            #   happen if we're using a non-blocking socket in a blocking thread.
            newsock.setblocking(1)
            newsock.settimeout(1)
            try:
                return peek_ssl_header()
            except Exception:
                return False


# set globally defined SSL socket implementation class
ssl.SSLContext.sslsocket_class = DuplexSocket


class GenericProxy(object):
    # TODO: move methods to different class?
    @classmethod
    def create_ssl_cert(cls, serial_number=None):
        cert_pem_file = get_cert_pem_file_path()
        return generate_ssl_cert(cert_pem_file, serial_number=serial_number)

    @classmethod
    def get_flask_ssl_context(cls, serial_number=None):
        if config.USE_SSL:
            _, cert_file_name, key_file_name = cls.create_ssl_cert(serial_number=serial_number)
            return cert_file_name, key_file_name
        return None


class UrlMatchingForwarder(ProxyListener):
    """
    ProxyListener that matches URLs to a base url pattern, and if the request url matches the
    pattern, forwards it to
    a forward_url. See TestUrlMatchingForwarder for how it behaves.
    """

    def __init__(self, base_url: str, forward_url: str) -> None:
        super().__init__()
        self.base_url = urlparse(base_url)
        self.forward_url = urlparse(forward_url)

    def forward_request(self, method, path, data, headers):
        host = headers.get("Host", "")

        if not self.matches(host, path):
            return True

        # build forward url
        forward_url = self.build_forward_url(host, path)

        # update headers
        headers["Host"] = forward_url.netloc

        # TODO: set proxy headers like x-forwarded-for?

        return self.do_forward(method, forward_url.geturl(), headers, data)

    def do_forward(self, method, url, headers, data):
        return requests.request(method, url, data=data, headers=headers, stream=True, verify=False)

    def matches(self, host, path):
        # TODO: refine matching default ports (80, 443 if scheme is https). Example:
        #  http://localhost:80 matches
        #  http://localhost) check host rule. Can lead to problems with 443-4566 edge proxy
        #  forwarding if not enabled
        if self.base_url.netloc:
            stripped_netloc, _, port = self.base_url.netloc.rpartition(":")
            if host != self.base_url.netloc and (
                host != stripped_netloc or port not in ["80", "443"]
            ):
                return False

        # check path components
        if self.base_url.path == "/":
            if path.startswith("/"):
                return True

        path_parts = path.split("/")
        base_path_parts = self.base_url.path.split("/")

        if len(base_path_parts) > len(path_parts):
            return False

        for i, component in enumerate(base_path_parts):
            if component != path_parts[i]:
                return False

        return True

    def build_forward_url(self, host, path):
        # build forward url
        if self.forward_url.hostname:
            forward_host = self.forward_url.scheme + "://" + self.forward_url.netloc
        else:
            forward_host = host
        forward_path_root = self.forward_url.path
        forward_path = path[len(self.base_url.path) :]  # strip base path

        # avoid double slashes
        if forward_path and not forward_path_root.endswith("/"):
            if not forward_path.startswith("/"):
                forward_path = "/" + forward_path

        forward_url = forward_host + forward_path_root + forward_path

        return urlparse(forward_url)


class EndpointProxy(ProxyListener):
    def __init__(self, base_url: str, forward_url: str) -> None:
        super().__init__()
        self.forwarder = UrlMatchingForwarder(
            base_url=base_url,
            forward_url=forward_url,
        )

    def forward_request(self, method, path, data, headers):
        return self.forwarder.forward_request(method, path, data, headers)

    def register(self):
        ProxyListener.DEFAULT_LISTENERS.append(self)

    def unregister(self):
        try:
            ProxyListener.DEFAULT_LISTENERS.remove(self)
        except ValueError:
            pass


class FakeEndpointProxyServer(Server):
    """
    Makes an EndpointProxy behave like a Server. You can use this to create transparent
    multiplexing behavior.
    """

    endpoint: EndpointProxy

    def __init__(self, endpoint: EndpointProxy) -> None:
        self.endpoint = endpoint
        self._shutdown_event = threading.Event()

        self._url = self.endpoint.forwarder.base_url
        super().__init__(self._url.port, self._url.hostname)

    @property
    def url(self):
        return self._url.geturl()

    def do_run(self):
        self.endpoint.register()
        try:
            self._shutdown_event.wait()
        finally:
            self.endpoint.unregister()

    def do_shutdown(self):
        self._shutdown_event.set()
        self.endpoint.unregister()


async def _accept_connection2(self, protocol_factory, conn, extra, sslcontext, *args, **kwargs):
    is_ssl_socket = DuplexSocket.is_ssl_socket(conn)
    if is_ssl_socket is False:
        sslcontext = None
    result = await _accept_connection2_orig(
        self, protocol_factory, conn, extra, sslcontext, *args, **kwargs
    )
    return result


# patch asyncio server to accept SSL and non-SSL traffic over same port
if hasattr(BaseSelectorEventLoop, "_accept_connection2") and not hasattr(
    BaseSelectorEventLoop, "_ls_patched"
):
    _accept_connection2_orig = BaseSelectorEventLoop._accept_connection2
    BaseSelectorEventLoop._accept_connection2 = _accept_connection2
    BaseSelectorEventLoop._ls_patched = True


def get_cert_pem_file_path():
    return os.path.join(config.dirs.cache, SERVER_CERT_PEM_FILE)


def start_proxy_server(
    port,
    bind_address=None,
    forward_url=None,
    use_ssl=None,
    update_listener: Optional[Union[ProxyListener, List[ProxyListener]]] = None,
    quiet=False,
    params=None,  # TODO: not being used - should be investigated/removed
    asynchronous=True,
    check_port=True,
):
    bind_address = bind_address if bind_address else BIND_HOST

    if update_listener is None:
        listeners = []
    elif isinstance(update_listener, list):
        listeners = update_listener
    else:
        listeners = [update_listener]

    def handler(request, data):
        parsed_url = urlparse(request.url)
        path_with_params = path_from_url(request.url)
        method = request.method
        headers = request.headers
        headers[HEADER_LOCALSTACK_REQUEST_URL] = str(request.url)

        response = modify_and_forward(
            method=method,
            path=path_with_params,
            data_bytes=data,
            headers=headers,
            forward_base_url=forward_url,
            listeners=listeners,
            client_address=request.remote_addr,
            server_address=parsed_url.netloc,
        )

        return response

    ssl_creds = (None, None)
    if use_ssl:
        install_predefined_cert_if_available()
        _, cert_file_name, key_file_name = GenericProxy.create_ssl_cert(serial_number=port)
        ssl_creds = (cert_file_name, key_file_name)

    result = http2_server.run_server(
        port, bind_address, handler=handler, asynchronous=asynchronous, ssl_creds=ssl_creds
    )
    if asynchronous and check_port:
        wait_for_port_open(port, sleep_time=0.2, retries=12)
    return result


def install_predefined_cert_if_available():
    try:
        from localstack_ext.bootstrap import install

        if config.SKIP_SSL_CERT_DOWNLOAD:
            LOG.debug("Skipping download of local SSL cert, as SKIP_SSL_CERT_DOWNLOAD=1")
            return
        install.setup_ssl_cert()
    except Exception:
        pass


def serve_flask_app(app, port, host=None, cors=True, asynchronous=False):
    if cors:
        CORS(app)
    if not config.DEBUG:
        logging.getLogger("werkzeug").setLevel(logging.ERROR)
    if not host:
        host = "0.0.0.0"
    ssl_context = None
    if not config.FORWARD_EDGE_INMEM:
        ssl_context = GenericProxy.get_flask_ssl_context(serial_number=port)
    app.config["ENV"] = "development"

    def noecho(*args, **kwargs):
        pass

    try:
        import click

        click.echo = noecho
    except Exception:
        pass

    def _run(*_):
        app.run(port=int(port), threaded=True, host=host, ssl_context=ssl_context)
        return app

    if asynchronous:
        return start_thread(_run)
    return _run()
