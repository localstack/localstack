from http import HTTPMethod
from typing import Optional, TypedDict

import requests
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration
from localstack.http import Response

from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..helpers import render_uri_with_path_parameters
from .core import RestApiIntegration

NO_BODY_METHODS = {
    HTTPMethod.OPTIONS,
    HTTPMethod.GET,
    HTTPMethod.HEAD,
}


class SimpleHttpRequest(TypedDict, total=False):
    method: HTTPMethod | str
    url: str
    params: Optional[dict[str, str | list[str]]]
    data: bytes
    headers: Optional[dict[str, str]]
    cookies: Optional[dict[str, str]]
    timeout: Optional[int]
    allow_redirects: Optional[bool]
    stream: Optional[bool]
    verify: Optional[bool]
    # TODO: check if there was a situation where we'd pass certs?
    cert: Optional[str | tuple[str, str]]


class BaseRestApiHttpIntegration(RestApiIntegration):
    @staticmethod
    def _get_default_headers(context: RestApiInvocationContext) -> dict[str, str]:
        # passing full context as the trace-id will probably also come from it
        # TODO: get right casing in case we can override them with mappings/override?
        return {
            "x-amzn-apigateway-api-id": context.api_id,
            "x-amzn-trace-id": "",  # TODO
            "user-agent": f"AmazonAPIGateway_{context.api_id}",
        }

    @staticmethod
    def _get_integration_timeout(integration: Integration) -> float:
        return int(integration.get("timeoutInMillis", 29000)) / 1000


class RestApiHttpIntegration(BaseRestApiHttpIntegration):
    """
    This is a REST API integration responsible to send a request to another HTTP API.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP"

    def invoke(self, context: RestApiInvocationContext) -> Response:
        integration_req: IntegrationRequest = context.integration_request
        method = integration_req["http_method"]

        default_apigw_headers = self._get_default_headers(context)
        default_apigw_headers.update(integration_req["headers"])

        request_parameters: SimpleHttpRequest = {
            "method": method,
            "url": integration_req["uri"],
            "params": integration_req["query_string_parameters"],
            "headers": default_apigw_headers,
        }

        if method not in NO_BODY_METHODS:
            request_parameters["data"] = integration_req["body"]

        # TODO: configurable timeout (29 by default) (check type and default value in provider)
        # integration: Integration = context.resource_method["methodIntegration"]
        # request_parameters["timeout"] = self._get_integration_timeout(integration)
        # TODO: check for redirects
        # request_parameters["allow_redirects"] = False

        request_response = requests.request(**request_parameters)

        return Response(
            response=request_response.content,
            status=request_response.status_code,
            headers=Headers(dict(request_response.headers)),
        )


class RestApiHttpProxyIntegration(BaseRestApiHttpIntegration):
    """
    This is a simplified REST API integration responsible to send a request to another HTTP API by proxying it almost
    directly.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP_PROXY"

    def invoke(self, context: RestApiInvocationContext) -> Response:
        invocation_req: InvocationRequest = context.invocation_request
        integration: Integration = context.resource_method["methodIntegration"]

        # if the integration method is defined and is not ANY, we can use it for the integration
        if not (method := integration["httpMethod"]) or method == "ANY":
            # otherwise, fallback to the request's method
            method = invocation_req["http_method"]

        integration_uri = context.resource_method["methodIntegration"]["uri"]
        uri = render_uri_with_path_parameters(
            integration_uri,
            path_parameters=invocation_req["path_parameters"],
        )

        default_apigw_headers = self._get_default_headers(context)

        request_headers = {
            key: ",".join(value) for key, value in invocation_req["multi_value_headers"].items()
        }
        # TODO: check which headers to pop
        request_headers.pop("Host", None)
        default_apigw_headers.update(request_headers)

        request_parameters: SimpleHttpRequest = {
            "method": method,
            "url": uri,
            "params": invocation_req["multi_value_query_string_parameters"],
            "headers": default_apigw_headers,
        }

        # TODO: validate this for HTTP_PROXY
        if method not in NO_BODY_METHODS:
            request_parameters["data"] = invocation_req["body"]

        # TODO: configurable timeout (29 by default) (check type and default value in provider)
        # request_parameters["timeout"] = self._get_integration_timeout(integration)

        request_response = requests.request(**request_parameters)

        response_headers = Headers(dict(request_response.headers))
        remapped = ["connection", "content-length", "date", "x-amzn-requestid"]
        for header in remapped:
            if value := request_response.headers.get(header):
                response_headers[f"x-amzn-remapped-{header}"] = value

        return Response(
            response=request_response.content,
            status=request_response.status_code,
            headers=response_headers,
        )
