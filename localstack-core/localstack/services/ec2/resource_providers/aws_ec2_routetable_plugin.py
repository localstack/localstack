from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2RouteTableProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::RouteTable"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_routetable import (
            EC2RouteTableProvider,
        )

        self.factory = EC2RouteTableProvider
