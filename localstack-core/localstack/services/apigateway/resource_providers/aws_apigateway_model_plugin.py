from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayModelProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Model"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_model import (
            ApiGatewayModelProvider,
        )

        self.factory = ApiGatewayModelProvider
