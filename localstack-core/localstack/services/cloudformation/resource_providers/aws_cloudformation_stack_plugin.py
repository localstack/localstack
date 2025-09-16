from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudFormationStackProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudFormation::Stack"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cloudformation.resource_providers.aws_cloudformation_stack import (
            CloudFormationStackProvider,
        )

        self.factory = CloudFormationStackProvider
