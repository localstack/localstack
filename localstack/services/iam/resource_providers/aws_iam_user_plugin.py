from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class IAMUserProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::IAM::User"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.iam.resource_providers.aws_iam_user import IAMUserProvider

        self.factory = IAMUserProvider
