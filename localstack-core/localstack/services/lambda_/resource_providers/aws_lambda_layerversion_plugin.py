from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaLayerVersionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::LayerVersion"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_layerversion import (
            LambdaLayerVersionProvider,
        )

        self.factory = LambdaLayerVersionProvider
