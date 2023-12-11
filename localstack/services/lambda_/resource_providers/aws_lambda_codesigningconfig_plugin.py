from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaCodeSigningConfigProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::CodeSigningConfig"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_codesigningconfig import (
            LambdaCodeSigningConfigProvider,
        )

        self.factory = LambdaCodeSigningConfigProvider
