from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2VPCProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::VPC"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_vpc import EC2VPCProvider

        self.factory = EC2VPCProvider
