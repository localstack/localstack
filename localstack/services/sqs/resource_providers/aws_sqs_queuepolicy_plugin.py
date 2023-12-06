from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SQSQueuePolicyProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SQS::QueuePolicy"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.sqs.resource_providers.aws_sqs_queuepolicy import (
            SQSQueuePolicyProvider,
        )

        self.factory = SQSQueuePolicyProvider
