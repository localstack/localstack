from .core import RestApiIntegrationPlugin


class RestApiHttpIntegration(RestApiIntegrationPlugin):
    """
    This is a REST API integration responsible to send a request to another HTTP API.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "http"


class RestApiHttpProxyIntegration(RestApiIntegrationPlugin):
    """
    This is a simplified REST API integration responsible to send a request to another HTTP API by proxying it almost
    directly.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/setup-http-integrations.html#api-gateway-set-up-http-proxy-integration-on-proxy-resource
    """

    name = "http_proxy"
