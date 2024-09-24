from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2SubnetProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::Subnet"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_subnet import EC2SubnetProvider

        self.factory = EC2SubnetProvider
