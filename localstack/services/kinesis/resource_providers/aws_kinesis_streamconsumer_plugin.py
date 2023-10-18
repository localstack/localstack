from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KinesisStreamConsumerProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Kinesis::StreamConsumer"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.kinesis.resource_providers.aws_kinesis_streamconsumer import (
            KinesisStreamConsumerProvider,
        )

        self.factory = KinesisStreamConsumerProvider
