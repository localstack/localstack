from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SNSTopicProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SNS::Topic"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.sns.resource_providers.aws_sns_topic import SNSTopicProvider

        self.factory = SNSTopicProvider
