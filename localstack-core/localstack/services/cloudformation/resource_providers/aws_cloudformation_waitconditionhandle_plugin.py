from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class CloudFormationWaitConditionHandleProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::CloudFormation::WaitConditionHandle"

    def __init__(self):
        self.factory: type[ResourceProvider] | None = None

    def load(self):
        from localstack.services.cloudformation.resource_providers.aws_cloudformation_waitconditionhandle import (
            CloudFormationWaitConditionHandleProvider,
        )

        self.factory = CloudFormationWaitConditionHandleProvider
