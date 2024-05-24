from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayAccountProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::Account"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_account import (
            ApiGatewayAccountProvider,
        )

        self.factory = ApiGatewayAccountProvider
