from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2SubnetRouteTableAssociationProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::SubnetRouteTableAssociation"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_subnetroutetableassociation import (
            EC2SubnetRouteTableAssociationProvider,
        )

        self.factory = EC2SubnetRouteTableAssociationProvider
