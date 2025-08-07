from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaEventInvokeConfigProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::EventInvokeConfig"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_eventinvokeconfig import (
            LambdaEventInvokeConfigProvider,
        )

        self.factory = LambdaEventInvokeConfigProvider
