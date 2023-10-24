from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayUsagePlanProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::UsagePlan"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_usageplan import (
            ApiGatewayUsagePlanProvider,
        )

        self.factory = ApiGatewayUsagePlanProvider
