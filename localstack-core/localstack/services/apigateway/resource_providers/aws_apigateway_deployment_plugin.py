from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayDeploymentProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Deployment"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_deployment import (
            ApiGatewayDeploymentProvider,
        )

        self.factory = ApiGatewayDeploymentProvider
