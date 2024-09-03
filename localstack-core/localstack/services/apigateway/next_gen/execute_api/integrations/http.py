import logging
from http import HTTPMethod
from typing import Optional, TypedDict

import requests
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration

from ..context import EndpointResponse, IntegrationRequest, RestApiInvocationContext
from ..gateway_response import ApiConfigurationError, IntegrationFailureError
from ..header_utils import build_multi_value_headers
from .core import RestApiIntegration

LOG = logging.getLogger(__name__)

NO_BODY_METHODS = {HTTPMethod.OPTIONS, HTTPMethod.GET, HTTPMethod.HEAD}


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
    def _get_integration_timeout(integration: Integration) -> float:
        return int(integration.get("timeoutInMillis", 29000)) / 1000


class RestApiHttpIntegration(BaseRestApiHttpIntegration):
    """
    This is a REST API integration responsible to send a request to another HTTP API.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP"

    def invoke(self, context: RestApiInvocationContext) -> EndpointResponse:
        integration_req: IntegrationRequest = context.integration_request
        method = integration_req["http_method"]
        uri = integration_req["uri"]

        request_parameters: SimpleHttpRequest = {
            "method": method,
            "url": uri,
            "params": integration_req["query_string_parameters"],
            "headers": integration_req["headers"],
        }

        if method not in NO_BODY_METHODS:
            request_parameters["data"] = integration_req["body"]

        # TODO: configurable timeout (29 by default) (check type and default value in provider)
        # integration: Integration = context.resource_method["methodIntegration"]
        # request_parameters["timeout"] = self._get_integration_timeout(integration)
        # TODO: check for redirects
        # request_parameters["allow_redirects"] = False
        try:
            request_response = requests.request(**request_parameters)

        except (requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema) as e:
            LOG.warning("Execution failed due to configuration error: Invalid endpoint address")
            LOG.debug("The URI specified for the HTTP/HTTP_PROXY integration is invalid: %s", uri)
            raise ApiConfigurationError("Internal server error") from e

        except (requests.exceptions.Timeout, requests.exceptions.SSLError) as e:
            # TODO make the exception catching more fine grained
            # this can be reproduced in AWS if you try to hit an HTTP endpoint which is HTTPS only like lambda URL
            LOG.warning("Execution failed due to a network error communicating with endpoint")
            raise IntegrationFailureError("Network error communicating with endpoint") from e

        except requests.exceptions.ConnectionError as e:
            raise ApiConfigurationError("Internal server error") from e

        return EndpointResponse(
            body=request_response.content,
            status_code=request_response.status_code,
            headers=Headers(dict(request_response.headers)),
        )


class RestApiHttpProxyIntegration(BaseRestApiHttpIntegration):
    """
    This is a simplified REST API integration responsible to send a request to another HTTP API by proxying it almost
    directly.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "HTTP_PROXY"

    def invoke(self, context: RestApiInvocationContext) -> EndpointResponse:
        integration_req: IntegrationRequest = context.integration_request
        method = integration_req["http_method"]
        uri = integration_req["uri"]

        multi_value_headers = build_multi_value_headers(integration_req["headers"])
        request_headers = {key: ",".join(value) for key, value in multi_value_headers.items()}

        request_parameters: SimpleHttpRequest = {
            "method": method,
            "url": uri,
            "params": integration_req["query_string_parameters"],
            "headers": request_headers,
        }

        # TODO: validate this for HTTP_PROXY
        if method not in NO_BODY_METHODS:
            request_parameters["data"] = integration_req["body"]

        # TODO: configurable timeout (29 by default) (check type and default value in provider)
        # integration: Integration = context.resource_method["methodIntegration"]
        # request_parameters["timeout"] = self._get_integration_timeout(integration)
        try:
            request_response = requests.request(**request_parameters)

        except (requests.exceptions.InvalidURL, requests.exceptions.InvalidSchema) as e:
            LOG.warning("Execution failed due to configuration error: Invalid endpoint address")
            LOG.debug("The URI specified for the HTTP/HTTP_PROXY integration is invalid: %s", uri)
            raise ApiConfigurationError("Internal server error") from e

        except (requests.exceptions.Timeout, requests.exceptions.SSLError):
            # TODO make the exception catching more fine grained
            # this can be reproduced in AWS if you try to hit an HTTP endpoint which is HTTPS only like lambda URL
            LOG.warning("Execution failed due to a network error communicating with endpoint")
            raise IntegrationFailureError("Network error communicating with endpoint")

        except requests.exceptions.ConnectionError:
            raise ApiConfigurationError("Internal server error")

        response_headers = Headers(dict(request_response.headers))

        return EndpointResponse(
            body=request_response.content,
            status_code=request_response.status_code,
            headers=response_headers,
        )
