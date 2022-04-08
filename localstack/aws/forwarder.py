"""
This module contains utilities to call a backend (e.g., an external service process like
DynamoDBLocal) from a service provider.
"""
from typing import Any, Callable, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

import requests
from botocore.awsrequest import AWSPreparedRequest
from botocore.parsers import create_parser
from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.api.core import (
    CommonServiceException,
    Request,
    RequestContext,
    ServiceRequest,
    ServiceRequestHandler,
    ServiceResponse,
)
from localstack.aws.skeleton import DispatchTable, create_dispatch_table
from localstack.aws.spec import load_service
from localstack.utils.aws import aws_stack
from localstack.utils.strings import to_bytes, to_str

HttpBackendResponse = Tuple[int, dict, Union[str, bytes]]


def ForwardingFallbackDispatcher(
    provider: object, request_forwarder: ServiceRequestHandler
) -> DispatchTable:
    """
    Wraps a provider with a request forwarder. It does by creating a new DispatchTable from the original
    provider, and wrapping each method with a fallthrough method that calls ``request_forwarder`` if the
    original provider raises a ``NotImplementedError``.

    :param provider: the ASF provider
    :param request_forwarder: callable that forwards the request (e.g., to a backend server)
    :return: a modified DispatchTable
    """
    table = create_dispatch_table(provider)

    for op, fn in table.items():
        table[op] = _wrap_with_fallthrough(fn, request_forwarder)

    return table


def _wrap_with_fallthrough(
    handler: ServiceRequestHandler, fallthrough_handler: ServiceRequestHandler
) -> ServiceRequestHandler:
    def _call(context, req) -> ServiceResponse:
        try:
            # handler will typically be an ASF provider method, and in case it hasn't been
            # implemented, we try to fall back to forwarding the request to the backend
            return handler(context, req)
        except NotImplementedError:
            return fallthrough_handler(context, req)

    return _call


def HttpFallbackDispatcher(provider: object, forward_url_getter: Callable[[], str]):
    return ForwardingFallbackDispatcher(provider, get_request_forwarder_http(forward_url_getter))


def get_request_forwarder_http(forward_url_getter: Callable[[], str]) -> ServiceRequestHandler:
    def _forward_request(context, service_request: ServiceRequest = None) -> ServiceResponse:
        if service_request is not None:
            local_context = create_aws_request_context(
                service_name=context.service.service_name,
                action=context.operation.name,
                parameters=service_request,
                region=context.region,
            )
            local_context.request.headers.extend(context.request.headers)
            context = local_context
        return forward_request(context, forward_url_getter)

    return _forward_request


def forward_request(
    context: RequestContext, forward_url_getter: Callable[[], str]
) -> ServiceResponse:
    def _call_http_backend(context: RequestContext) -> HttpBackendResponse:
        return call_http_backend(context, forward_url=forward_url_getter())

    return dispatch_to_backend(context, _call_http_backend)


def dispatch_to_backend(
    context: RequestContext,
    http_request_dispatcher: Callable[[RequestContext], HttpBackendResponse],
    include_response_metadata=False,
) -> ServiceResponse:
    """
    Dispatch the given request to a backend by using the `request_forwarder` function to
    fetch an HTTP response, converting it to a ServiceResponse.
    :param context: the request context
    :param http_request_dispatcher: dispatcher that performs the request and returns an HTTP response
    :param include_response_metadata: whether to include boto3 response metadata in the response
    :return:
    """
    status, headers, content = http_request_dispatcher(context)

    operation_model = context.operation
    response_dict = {  # this is what botocore.endpoint.convert_to_response_dict normally does
        "headers": dict(headers.items()),  # boto doesn't like werkzeug headers
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
            sender_fault=("Type" in error),
        )

    if not include_response_metadata:
        response.pop("ResponseMetadata", None)

    return response


def call_http_backend(context: RequestContext, forward_url: str) -> HttpBackendResponse:
    response = requests.request(
        method=context.request.method,
        url=forward_url,
        headers=context.request.headers,
        data=context.request.data,
    )
    return response.status_code, response.headers, response.content


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


def create_http_request(aws_request: AWSPreparedRequest) -> Request:
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

    return Request(
        method=aws_request.method,
        path=split_url.path,
        query_string=split_url.query,
        headers=headers,
        body=aws_request.body,
        server=server,
    )
