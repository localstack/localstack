from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2NetworkAclProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::NetworkAcl"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_networkacl import (
            EC2NetworkAclProvider,
        )

        self.factory = EC2NetworkAclProvider
