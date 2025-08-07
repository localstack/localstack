from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SQSQueueProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SQS::Queue"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.sqs.resource_providers.aws_sqs_queue import SQSQueueProvider

        self.factory = SQSQueueProvider
