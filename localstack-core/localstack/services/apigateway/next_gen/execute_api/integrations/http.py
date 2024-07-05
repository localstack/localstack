from http import HTTPMethod

import requests
from werkzeug.datastructures import Headers

from localstack.http import Response

from ..context import IntegrationRequest, InvocationRequest, RestApiInvocationContext
from ..helpers import render_uri_with_path_parameters
from .core import RestApiIntegration

NO_BODY_METHODS = {
    HTTPMethod.OPTIONS,
    HTTPMethod.GET,
    HTTPMethod.HEAD,
}


class RestApiHttpIntegration(RestApiIntegration):
    """
    This is a REST API integration responsible to send a request to another HTTP API.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP"

    def invoke(self, context: RestApiInvocationContext) -> Response:
        integration_req: IntegrationRequest = context.integration_request
        method = integration_req["http_method"]

        # TODO: get right casing in case we can override them with mappings/override?
        default_apigw_headers = {
            "x-amzn-apigateway-api-id": context.api_id,
            "x-amzn-trace-id": "",  # TODO
            "user-agent": f"AmazonAPIGateway_{context.api_id}",
            "accept-encoding": "gzip,deflate",
        }
        default_apigw_headers.update(integration_req["headers"])

        request_parameters = {
            "method": method,
            "url": integration_req["uri"],
            "params": integration_req["query_string_parameters"],
            "headers": default_apigw_headers,
        }

        if method not in NO_BODY_METHODS:
            request_parameters["data"] = integration_req["body"]

        request_response = requests.request(**request_parameters)

        response = Response(
            response=request_response.content,
            status=request_response.status_code,
            headers=Headers(dict(request_response.headers)),
        )

        return response


class RestApiHttpProxyIntegration(RestApiIntegration):
    """
    This is a simplified REST API integration responsible to send a request to another HTTP API by proxying it almost
    directly.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP_PROXY"

    def invoke(self, context: RestApiInvocationContext) -> Response:
        invocation_req: InvocationRequest = context.invocation_request
        integration_uri = context.resource_method["methodIntegration"]["uri"]
        uri = render_uri_with_path_parameters(
            integration_uri,
            path_parameters=invocation_req["path_parameters"],
        )

        # TODO: get right casing in case we can override them with mappings/override?
        default_apigw_headers = {
            "x-amzn-apigateway-api-id": context.api_id,
            "x-amzn-trace-id": "",  # TODO
            "user-agent": f"AmazonAPIGateway_{context.api_id}",
            "accept-encoding": "gzip,deflate",
        }
        headers = {
            key: ",".join(value) for key, value in invocation_req["multi_value_headers"].items()
        }
        # TODO: check which headers to pop
        headers.pop("Host", None)

        default_apigw_headers.update(headers)

        method = invocation_req["http_method"]
        request_parameters = {
            "method": invocation_req["http_method"],
            "url": uri,
            "params": invocation_req["multi_value_query_string_parameters"],
            "headers": default_apigw_headers,
        }

        # TODO: validate this
        if method not in NO_BODY_METHODS:
            request_parameters["data"] = invocation_req["body"]

        request_response = requests.request(**request_parameters)

        response_headers = Headers(dict(request_response.headers))
        remapped = ["connection", "content-length", "date", "x-amzn-requestid"]
        for header in remapped:
            if value := request_response.headers.get(header):
                response_headers[f"x-amzn-remapped-{header}"] = value

        response = Response(
            response=request_response.content,
            status=request_response.status_code,
            headers=response_headers,
        )

        return response
