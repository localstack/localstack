from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaPermissionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::Permission"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_permission import (
            LambdaPermissionProvider,
        )

        self.factory = LambdaPermissionProvider
