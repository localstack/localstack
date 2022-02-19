"""
This module provides tools to call moto using moto and botocore internals without going through the moto HTTP server.
"""
import sys
from functools import lru_cache
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

from botocore.awsrequest import AWSPreparedRequest
from botocore.parsers import create_parser
from moto.backends import get_backend as get_moto_backend
from moto.core.utils import BackendDict
from moto.server import RegexConverter
from werkzeug.datastructures import Headers
from werkzeug.routing import Map, Rule

from localstack import __version__ as localstack_version
from localstack import config
from localstack.aws.api import (
    CommonServiceException,
    HttpRequest,
    HttpResponse,
    RequestContext,
    ServiceResponse,
)
from localstack.aws.api.core import ServiceRequest, ServiceRequestHandler
from localstack.aws.skeleton import DispatchTable, create_dispatch_table
from localstack.aws.spec import load_service
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes, to_str

MotoResponse = Tuple[int, dict, Union[str, bytes]]
MotoDispatcher = Callable[[HttpRequest, str, dict], MotoResponse]

user_agent = f"Localstack/{localstack_version} Python/{sys.version.split(' ')[0]}"


def call_moto(context: RequestContext) -> ServiceResponse:
    """
    Call moto with the given request context and receive a parsed ServiceResponse.

    :param context: the request context
    :return: a serialized AWS ServiceResponse (same as boto3 would return)
    """
    status, headers, content = dispatch_to_moto(context)

    operation_model = context.operation
    response_dict = {  # this is what botocore.endpoint.convert_to_response_dict normally does
        "headers": headers,
        "status_code": status,
        "body": to_bytes(content),
        "context": {
            "operation_name": operation_model.name,
        },
    }

    parser = create_parser(context.service.protocol)
    response = parser.parse(response_dict, operation_model.output_shape)

    if status >= 301:
        error = response["Error"]
        raise CommonServiceException(
            code=error.get("Code", "UnknownError"),
            status_code=status,
            message=error.get("Message", ""),
        )

    return response


def call_moto_with_request(
    context: RequestContext, service_request: Union[Mapping[str, Any], ServiceRequest]
) -> ServiceResponse:
    """
    Like `call_moto`, but you can pass a modified version of the service request before calling moto. The caveat is
    that a new HTTP request has to be created. The service_request is serialized into a new RequestContext object,
    and headers from the old request are merged into the new one.

    :param context: the original request context
    :param service_request: the dictionary containing the service request parameters
    :return: a serialized AWS ServiceResponse (same as boto3 would return)
    """
    local_context = create_aws_request_context(
        service_name=context.service.service_name,
        action=context.operation.name,
        parameters=service_request,
        region=context.region,
    )

    local_context.request.headers.extend(context.request.headers)

    return call_moto(local_context)


def proxy_moto(context: RequestContext) -> HttpResponse:
    """
    Similar to ``call``, only that ``proxy`` does not parse the HTTP response into a ServiceResponse, but instead
    returns directly the HTTP response. This can be useful to pass through moto's response directly to the client.

    :param context: the request context
    :return: the HttpResponse from moto
    """
    status, headers, content = dispatch_to_moto(context)

    return HttpResponse(response=content, status=status, headers=headers)


def MotoFallbackDispatcher(provider: object) -> DispatchTable:
    """
    Wraps a provider with a moto fallthrough mechanism. It does by creating a new DispatchTable from the original
    provider, and wrapping each method with a fallthrough method that calls ``request`` if the original provider
    raises a ``NotImplementedError``.

    :param provider: the ASF provider
    :return: a modified DispatchTable
    """
    table = create_dispatch_table(provider)

    for op, fn in table.items():
        table[op] = _wrap_with_fallthrough(fn)

    return table


def _wrap_with_fallthrough(handler: ServiceRequestHandler) -> ServiceRequestHandler:
    def _call(context, req) -> ServiceResponse:
        try:
            # handler will typically be an ASF provider method, and in case it hasn't been implemented, we try to
            # fall through to moto
            return handler(context, req)
        except NotImplementedError:
            return proxy_moto(context)

    return _call


def dispatch_to_moto(context: RequestContext) -> MotoResponse:
    """
    Internal method to dispatch the request to moto without changing moto's dispatcher output.
    :param context: the request context
    :return: the response from moto
    """
    service = context.service
    request = context.request

    # hack to avoid call to request.form (see moto's BaseResponse.dispatch)
    request.body = request.data

    # this is where we skip the HTTP roundtrip between the moto server and the boto client
    dispatch = get_dispatcher(service.service_name, request.path)

    return dispatch(request, request.url, request.headers)


def get_dispatcher(service: str, path: str) -> MotoDispatcher:
    url_map = get_moto_routing_table(service)

    if len(url_map._rules) == 1:
        # in most cases, there will only be one dispatch method in the list of urls, so no need to do matching
        rule = next(url_map.iter_rules())
        return rule.endpoint

    matcher = url_map.bind(config.LOCALSTACK_HOSTNAME)
    endpoint, _ = matcher.match(path_info=path)
    return endpoint


@lru_cache()
def get_moto_routing_table(service: str) -> Map:
    """Cached version of load_moto_routing_table."""
    return load_moto_routing_table(service)


def load_moto_routing_table(service: str) -> Map:
    """
    Creates from moto service url_paths a werkzeug URL rule map that can be used to locate moto methods to dispatch
    requests to.

    :param service: the service to get the map for.
    :return: a new Map object
    """
    # code from moto.server.create_backend_app
    backend_dict: BackendDict = get_moto_backend(service)
    if "us-east-1" in backend_dict:
        backend = backend_dict["us-east-1"]
    else:
        backend = backend_dict["global"]

    url_map = Map()
    url_map.converters["regex"] = RegexConverter

    for url_path, handler in backend.flask_paths.items():
        # endpoints are annotated as string in werkzeug, but don't have to be
        url_map.add(Rule(url_path, endpoint=handler))

    return url_map


def create_aws_request_context(
    service_name: str,
    action: str,
    parameters: Mapping[str, Any] = None,
    region: str = None,
    endpoint_url: Optional[str] = None,
) -> RequestContext:
    """
    This is a stripped-down version of what the botocore client does to perform an HTTP request from a client call. A
    client call looks something like this: boto3.client("sqs").create_queue(QueueName="myqueue"), which will be
    serialized into an HTTP request. This method does the same, without performing the actual request, and with a
    more low-level interface. An equivalent call would be

         create_aws_request_context("sqs", "CreateQueue", {"QueueName": "myqueue"})

    :param service_name: the AWS service
    :param action: the action to invoke
    :param parameters: the invocation parameters
    :param region: the region name (default is us-east-1)
    :param endpoint_url: the endpoint to call (defaults to localstack)
    :return: a RequestContext object that describes this request
    """
    if parameters is None:
        parameters = {}
    if region is None:
        region = config.AWS_REGION_US_EAST_1

    service = load_service(service_name)
    operation = service.operation_model(action)

    # we re-use botocore internals here to serialize the HTTP request, but don't send it
    client = aws_stack.connect_to_service(
        service_name, endpoint_url=endpoint_url, region_name=region
    )
    request_context = {
        "client_region": region,
        "has_streaming_input": operation.has_streaming_input,
        "auth_type": operation.auth_type,
    }
    request_dict = client._convert_to_request_dict(parameters, operation, context=request_context)
    aws_request = client._endpoint.create_request(request_dict, operation)

    context = RequestContext()
    context.service = service
    context.operation = operation
    context.region = region
    context.request = create_http_request(aws_request)

    return context


def create_http_request(aws_request: AWSPreparedRequest) -> HttpRequest:
    # create HttpRequest from AWSRequest
    split_url = urlsplit(aws_request.url)
    host = split_url.netloc.split(":")
    if len(host) == 1:
        server = (to_str(host[0]), None)
    elif len(host) == 2:
        server = (to_str(host[0]), int(host[1]))
    else:
        raise ValueError

    # prepare the RequestContext
    headers = Headers()
    for k, v in aws_request.headers.items():
        headers[k] = v

    return HttpRequest(
        method=aws_request.method,
        path=split_url.path,
        query_string=split_url.query,
        headers=headers,
        body=aws_request.body,
        server=server,
    )
