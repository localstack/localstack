from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudFormationMacroProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudFormation::Macro"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cloudformation.resource_providers.aws_cloudformation_macro import (
            CloudFormationMacroProvider,
        )

        self.factory = CloudFormationMacroProvider
