from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2VPCEndpointProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::VPCEndpoint"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_vpcendpoint import (
            EC2VPCEndpointProvider,
        )

        self.factory = EC2VPCEndpointProvider
