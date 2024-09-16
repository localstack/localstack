from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class KinesisFirehoseDeliveryStreamProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::KinesisFirehose::DeliveryStream"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.kinesisfirehose.resource_providers.aws_kinesisfirehose_deliverystream import (
            KinesisFirehoseDeliveryStreamProvider,
        )

        self.factory = KinesisFirehoseDeliveryStreamProvider
