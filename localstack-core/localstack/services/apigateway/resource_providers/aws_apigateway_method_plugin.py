from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayMethodProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Method"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_method import (
            ApiGatewayMethodProvider,
        )

        self.factory = ApiGatewayMethodProvider
