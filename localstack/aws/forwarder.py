"""
This module contains utilities to call a backend (e.g., an external service process like
DynamoDBLocal) from a service provider.
"""
from typing import Any, Callable, Mapping, Optional
from urllib.parse import urlsplit

from botocore.awsrequest import AWSPreparedRequest, prepare_request_dict
from botocore.config import Config as BotoConfig
from werkzeug.datastructures import Headers

from localstack import config
from localstack.aws.api.core import (
    Request,
    RequestContext,
    ServiceRequest,
    ServiceRequestHandler,
    ServiceResponse,
)
from localstack.aws.client import parse_response, raise_service_exception
from localstack.aws.skeleton import DispatchTable, create_dispatch_table
from localstack.aws.spec import load_service
from localstack.http import Response
from localstack.http.proxy import forward
from localstack.utils.aws import aws_stack
from localstack.utils.strings import to_str


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


class NotImplementedAvoidFallbackError(NotImplementedError):
    pass


def _wrap_with_fallthrough(
    handler: ServiceRequestHandler, fallthrough_handler: ServiceRequestHandler
) -> ServiceRequestHandler:
    def _call(context, req) -> ServiceResponse:
        try:
            # handler will typically be an ASF provider method, and in case it hasn't been
            # implemented, we try to fall back to forwarding the request to the backend
            return handler(context, req)
        except NotImplementedAvoidFallbackError as e:
            # if the fallback has been explicitly disabled, don't pass on to the fallback
            raise e
        except NotImplementedError:
            pass

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
            # update the newly created context with non-payload specific request headers (the payload can differ from
            # the original request, f.e. it could be JSON encoded now while the initial request was CBOR encoded)
            headers = Headers(context.request.headers)
            headers.pop("Content-Type", None)
            headers.pop("Content-Length", None)
            local_context.request.headers.update(headers)
            context = local_context
        return forward_request(context, forward_url_getter)

    return _forward_request


def forward_request(
    context: RequestContext, forward_url_getter: Callable[[], str]
) -> ServiceResponse:
    def _call_http_backend(context: RequestContext) -> Response:
        return forward(context.request, forward_url_getter())

    return dispatch_to_backend(context, _call_http_backend)


def dispatch_to_backend(
    context: RequestContext,
    http_request_dispatcher: Callable[[RequestContext], Response],
    include_response_metadata=False,
) -> ServiceResponse:
    """
    Dispatch the given request to a backend by using the `request_forwarder` function to
    fetch an HTTP response, converting it to a ServiceResponse.
    :param context: the request context
    :param http_request_dispatcher: dispatcher that performs the request and returns an HTTP response
    :param include_response_metadata: whether to include boto3 response metadata in the response
    :return: parsed service response
    :raises ServiceException: if the dispatcher returned an error response
    """
    http_response = http_request_dispatcher(context)
    parsed_response = parse_response(context.operation, http_response, include_response_metadata)
    raise_service_exception(http_response, parsed_response)
    return parsed_response


# boto config deactivating param validation to forward to backends (backends are responsible for validating params)
_non_validating_boto_config = BotoConfig(parameter_validation=False)


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

    # we re-use botocore internals here to serialize the HTTP request,
    # but deactivate validation (validation errors should be handled by the backend)
    # and don't send it yet
    client = aws_stack.connect_to_service(
        service_name,
        endpoint_url=endpoint_url,
        region_name=region,
        config=_non_validating_boto_config,
    )
    request_context = {
        "client_region": region,
        "has_streaming_input": operation.has_streaming_input,
        "auth_type": operation.auth_type,
    }

    # The endpoint URL is mandatory here, set a dummy if not given (doesn't _need_ to be localstack specific)
    if not endpoint_url:
        endpoint_url = "http://localhost.localstack.cloud"
    request_dict = client._convert_to_request_dict(
        parameters, operation, endpoint_url, context=request_context
    )

    if auth_path := request_dict.get("auth_path"):
        # botocore >= 1.28 might modify the url path of the request dict (specifically for S3).
        # It will then set the original url path as "auth_path". If the auth_path is set, we reset the url_path.
        # Afterwards the request needs to be prepared again.
        request_dict["url_path"] = auth_path
        prepare_request_dict(
            request_dict,
            endpoint_url=endpoint_url,
            user_agent=client._client_config.user_agent,
            context=request_context,
        )

    aws_request: AWSPreparedRequest = client._endpoint.create_request(request_dict, operation)
    context = RequestContext()
    context.service = service
    context.operation = operation
    context.region = region
    context.request = create_http_request(aws_request)
    context.service_request = parameters

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
