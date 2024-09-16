from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudFormationWaitConditionHandleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudFormation::WaitConditionHandle"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.cloudformation.resource_providers.aws_cloudformation_waitconditionhandle import (
            CloudFormationWaitConditionHandleProvider,
        )

        self.factory = CloudFormationWaitConditionHandleProvider
