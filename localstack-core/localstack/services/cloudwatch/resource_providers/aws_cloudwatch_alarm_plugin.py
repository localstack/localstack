from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudWatchAlarmProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudWatch::Alarm"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cloudwatch.resource_providers.aws_cloudwatch_alarm import (
            CloudWatchAlarmProvider,
        )

        self.factory = CloudWatchAlarmProvider
