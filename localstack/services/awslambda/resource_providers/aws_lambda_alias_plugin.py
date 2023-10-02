from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaAliasProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Alias"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.awslambda.resource_providers.aws_lambda_alias import (
            LambdaAliasProvider,
        )

        self.factory = LambdaAliasProvider
