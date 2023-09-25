"""
This module contains utilities to call a backend (e.g., an external service process like
DynamoDBLocal) from a service provider.
"""

from typing import Any, Callable, Mapping, Optional, Union

from botocore.awsrequest import AWSPreparedRequest, prepare_request_dict
from botocore.config import Config as BotoConfig
from werkzeug.datastructures import Headers

from localstack.aws.api.core import (
    RequestContext,
    ServiceRequest,
    ServiceRequestHandler,
    ServiceResponse,
)
from localstack.aws.client import create_http_request, parse_response, raise_service_exception
from localstack.aws.connect import connect_to
from localstack.aws.skeleton import DispatchTable, create_dispatch_table
from localstack.aws.spec import load_service
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.http import Response
from localstack.http.proxy import Proxy


class AwsRequestProxy:
    """
    Implements the ``ServiceRequestHandler`` protocol to forward AWS requests to a backend. It is stateful and uses a
    ``Proxy`` instance for re-using client connections to the backend.
    """

    def __init__(
        self,
        endpoint_url: str,
        parse_response: bool = True,
        include_response_metadata: bool = False,
    ):
        """
        Create a new AwsRequestProxy. ``parse_response`` control the return behavior of ``forward``. If
        ``parse_response`` is set, then ``forward`` parses the HTTP response from the backend and returns a
        ``ServiceResponse``, otherwise it returns the raw HTTP ``Response`` object.

        :param endpoint_url: the backend to proxy the requests to, used as ``forward_base_url`` for the ``Proxy``.
        :param parse_response: whether to parse the response before returning it
        :param include_response_metadata: include AWS response metadata, only used with ``parse_response=True``
        """
        self.endpoint_url = endpoint_url
        self.parse_response = parse_response
        self.include_response_metadata = include_response_metadata
        self.proxy = Proxy(forward_base_url=endpoint_url)

    def __call__(
        self,
        context: RequestContext,
        service_request: ServiceRequest = None,
    ) -> Optional[Union[ServiceResponse, Response]]:
        """Method to satisfy the ``ServiceRequestHandler`` protocol."""
        return self.forward(context, service_request)

    def forward(
        self,
        context: RequestContext,
        service_request: ServiceRequest = None,
    ) -> Optional[Union[ServiceResponse, Response]]:
        """
        Forwards the given request to the backend configured by ``endpoint_url``.

        :param context: the original request context of the incoming request
        :param service_request: optionally a new service
        :return:
        """
        if service_request is not None:
            # if a service request is passed then we need to create a new request context
            context = self.new_request_context(context, service_request)

        http_response = self.proxy.forward(context.request, forward_path=context.request.path)
        if not self.parse_response:
            return http_response
        parsed_response = parse_response(
            context.operation, http_response, self.include_response_metadata
        )
        raise_service_exception(http_response, parsed_response)
        return parsed_response

    def new_request_context(self, original: RequestContext, service_request: ServiceRequest):
        context = create_aws_request_context(
            service_name=original.service.service_name,
            action=original.operation.name,
            parameters=service_request,
            region=original.region,
        )
        # update the newly created context with non-payload specific request headers (the payload can differ from
        # the original request, f.e. it could be JSON encoded now while the initial request was CBOR encoded)
        headers = Headers(original.request.headers)
        headers.pop("Content-Type", None)
        headers.pop("Content-Length", None)
        context.request.headers.update(headers)
        return context


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


def HttpFallbackDispatcher(provider: object, forward_url_getter: Callable[[str, str], str]):
    return ForwardingFallbackDispatcher(provider, get_request_forwarder_http(forward_url_getter))


def get_request_forwarder_http(
    forward_url_getter: Callable[[str, str], str],
) -> ServiceRequestHandler:
    """
    Returns a ServiceRequestHandler that creates for each invocation a new AwsRequestProxy with the result of
    forward_url_getter. Note that this is an inefficient method of proxying, since for every call a new client
    connection has to be established. Try to instead use static forward URL values and use ``AwsRequestProxy`` directly.

    :param forward_url_getter: a factory method for returning forward base urls for the proxy
    :return: a ServiceRequestHandler acting as a proxy
    """

    def _forward_request(
        context: RequestContext, service_request: ServiceRequest = None
    ) -> ServiceResponse:
        return AwsRequestProxy(forward_url_getter(context.account_id, context.region)).forward(
            context, service_request
        )

    return _forward_request


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
        region = AWS_REGION_US_EAST_1

    service = load_service(service_name)
    operation = service.operation_model(action)

    # we re-use botocore internals here to serialize the HTTP request,
    # but deactivate validation (validation errors should be handled by the backend)
    # and don't send it yet
    client = connect_to.get_client(
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
    # pre-process the request args (some params are modified using botocore event handlers)
    parameters = client._emit_api_params(parameters, operation, request_context)
    request_dict = client._convert_to_request_dict(
        parameters, operation, endpoint_url, context=request_context
    )

    if auth_path := request_dict.get("auth_path"):
        # botocore >= 1.28 might modify the url path of the request dict (specifically for S3).
        # It will then set the original url path as "auth_path". If the auth_path is set, we reset the url_path.
        # Since botocore 1.31.2, botocore will strip the query from the `authPart`
        # We need to add it back from `requestUri` field
        # Afterwards the request needs to be prepared again.
        path, sep, query = request_dict["url_path"].partition("?")
        request_dict["url_path"] = f"{auth_path}{sep}{query}"
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
