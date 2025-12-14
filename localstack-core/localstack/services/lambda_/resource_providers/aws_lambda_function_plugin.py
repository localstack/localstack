from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import ResourceProvider
from localstack.services.cloudformation.resource_provider import CloudFormationResourceProviderPlugin

class LambdaFunctionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Function"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda__function import LambdaFunctionProvider

        self.factory = LambdaFunctionProvider
