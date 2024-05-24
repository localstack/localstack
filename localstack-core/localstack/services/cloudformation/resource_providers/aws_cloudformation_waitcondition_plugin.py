from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudFormationWaitConditionProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudFormation::WaitCondition"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.cloudformation.resource_providers.aws_cloudformation_waitcondition import (
            CloudFormationWaitConditionProvider,
        )

        self.factory = CloudFormationWaitConditionProvider
