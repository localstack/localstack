from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LambdaEventSourceMappingProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Lambda::EventSourceMapping"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.lambda_.resource_providers.aws_lambda_eventsourcemapping import (
            LambdaEventSourceMappingProvider,
        )

        self.factory = LambdaEventSourceMappingProvider
