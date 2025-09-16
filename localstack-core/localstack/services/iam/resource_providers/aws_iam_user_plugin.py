from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMUserProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::User"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.iam.resource_providers.aws_iam_user import IAMUserProvider

        self.factory = IAMUserProvider
