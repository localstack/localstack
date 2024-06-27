from .core import RestApiIntegrationPlugin


# TODO: verify if we can create a global AWS integration type, or if we need subtypes with a sub namespace
class RestApiAwsIntegration(RestApiIntegrationPlugin):
    name = "aws"


class RestApiAwsProxyIntegration(RestApiIntegrationPlugin):
    name = "aws_proxy"
