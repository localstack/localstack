from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class ApiGatewayDomainNameProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::ApiGateway::DomainName"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.apigateway.resource_providers.aws_apigateway_domainname import (
            ApiGatewayDomainNameProvider,
        )

        self.factory = ApiGatewayDomainNameProvider
