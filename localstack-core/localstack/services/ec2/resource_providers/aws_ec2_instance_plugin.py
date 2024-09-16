from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2InstanceProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::Instance"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_instance import EC2InstanceProvider

        self.factory = EC2InstanceProvider
