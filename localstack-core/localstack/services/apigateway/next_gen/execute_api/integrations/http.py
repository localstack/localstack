from .core import RestApiIntegrationPlugin


class RestApiHttpIntegration(RestApiIntegrationPlugin):
    name = "http"


class RestApiHttpProxyIntegration(RestApiIntegrationPlugin):
    name = "http_proxy"
