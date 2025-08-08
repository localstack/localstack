from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayStageProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Stage"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_stage import (
            ApiGatewayStageProvider,
        )

        self.factory = ApiGatewayStageProvider
