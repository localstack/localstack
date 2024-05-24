from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class SSMPatchBaselineProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::SSM::PatchBaseline"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.ssm.resource_providers.aws_ssm_patchbaseline import (
            SSMPatchBaselineProvider,
        )

        self.factory = SSMPatchBaselineProvider
