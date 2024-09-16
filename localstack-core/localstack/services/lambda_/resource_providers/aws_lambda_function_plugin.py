from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaFunctionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Function"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_function import (
            LambdaFunctionProvider,
        )

        self.factory = LambdaFunctionProvider
