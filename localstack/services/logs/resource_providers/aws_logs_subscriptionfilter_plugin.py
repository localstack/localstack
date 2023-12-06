from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class LogsSubscriptionFilterProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::Logs::SubscriptionFilter"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.logs.resource_providers.aws_logs_subscriptionfilter import (
            LogsSubscriptionFilterProvider,
        )

        self.factory = LogsSubscriptionFilterProvider
