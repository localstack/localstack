from typing import Any, Callable, Mapping, Tuple, Union

import requests
from botocore.parsers import create_parser

from localstack.aws.api.core import (
    CommonServiceException,
    RequestContext,
    ServiceRequest,
    ServiceRequestHandler,
    ServiceResponse,
)
from localstack.aws.skeleton import DispatchTable, create_dispatch_table
from localstack.services.moto import create_aws_request_context
from localstack.utils.strings import to_bytes

# TODO: unify with MotoResponse
ForwardedResponse = Tuple[int, dict, Union[str, bytes]]
ServiceRequestType = Union[Mapping[str, Any], ServiceRequest]


def ForwardingFallbackDispatcher(provider: object, request_forwarder: Callable) -> DispatchTable:
    """
    Wraps a provider with a request forwarder. It does by creating a new DispatchTable from the original
    provider, and wrapping each method with a fallthrough method that calls ``request_forwarder`` if the
    original provider raises a ``NotImplementedError``.

    :param provider: the ASF provider
    :param request_forwarder: callable that forwards the request to a backend server
    :return: a modified DispatchTable
    """
    table = create_dispatch_table(provider)

    for op, fn in table.items():
        table[op] = _wrap_with_fallthrough(fn, request_forwarder)

    return table


# TODO: unify with function in moto.py
def _wrap_with_fallthrough(
    handler: ServiceRequestHandler, request_forwarder: Callable
) -> ServiceRequestHandler:
    def _call(context, req) -> ServiceResponse:
        try:
            # handler will typically be an ASF provider method, and in case it hasn't been
            # implemented, we try to fall back to forwarding the request to the backend
            return handler(context, req)
        except NotImplementedError:
            return request_forwarder(context)

    return _call


def ExternalProcessFallbackDispatcher(provider: object, forward_url_getter: Callable):
    return ForwardingFallbackDispatcher(provider, request_forwarder(forward_url_getter))


def request_forwarder(forward_url_getter: Callable):
    def _forward_request(context, service_request: ServiceRequestType = None):
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


def forward_request(context: RequestContext, forward_url_getter: Callable):
    def _call_http_backend(context):
        return call_http_backend(context, forward_url=forward_url_getter())

    return dispatch_to_backend(context, _call_http_backend)


# TODO: unify with call_moto(..) in moto.py
def dispatch_to_backend(
    context: RequestContext, request_forwarder: Callable, include_response_metadata=False
) -> ServiceResponse:
    status, headers, content = request_forwarder(context)

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
        )

    if not include_response_metadata:
        response.pop("ResponseMetadata", None)

    return response


def call_http_backend(context: RequestContext, forward_url: str) -> ForwardedResponse:
    response = requests.request(
        method=context.request.method,
        url=forward_url,
        headers=context.request.headers,
        data=context.request.data,
    )
    return response.status_code, response.headers, response.content
