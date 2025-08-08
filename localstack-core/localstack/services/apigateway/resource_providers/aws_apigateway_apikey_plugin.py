from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayApiKeyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::ApiKey"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_apikey import (
            ApiGatewayApiKeyProvider,
        )

        self.factory = ApiGatewayApiKeyProvider
