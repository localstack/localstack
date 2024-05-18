from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayUsagePlanKeyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::UsagePlanKey"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_usageplankey import (
            ApiGatewayUsagePlanKeyProvider,
        )

        self.factory = ApiGatewayUsagePlanKeyProvider
