from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class EC2KeyPairProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::EC2::KeyPair"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.ec2.resource_providers.aws_ec2_keypair import EC2KeyPairProvider

        self.factory = EC2KeyPairProvider
