from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2InternetGatewayProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::InternetGateway"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_internetgateway import (
            EC2InternetGatewayProvider,
        )

        self.factory = EC2InternetGatewayProvider
