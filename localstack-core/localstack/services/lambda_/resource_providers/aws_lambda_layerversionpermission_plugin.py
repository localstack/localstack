from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaLayerVersionPermissionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::LayerVersionPermission"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_layerversionpermission import (
            LambdaLayerVersionPermissionProvider,
        )

        self.factory = LambdaLayerVersionPermissionProvider
