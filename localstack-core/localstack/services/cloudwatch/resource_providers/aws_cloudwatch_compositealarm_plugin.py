from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudWatchCompositeAlarmProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudWatch::CompositeAlarm"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.cloudwatch.resource_providers.aws_cloudwatch_compositealarm import (
            CloudWatchCompositeAlarmProvider,
        )

        self.factory = CloudWatchCompositeAlarmProvider
