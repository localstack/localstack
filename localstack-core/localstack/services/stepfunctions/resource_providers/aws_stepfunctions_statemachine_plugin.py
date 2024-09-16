from typing import Optional, Type

from localstack.services.cloudformation.resource_provider import (
    CloudFormationResourceProviderPlugin,
    ResourceProvider,
)


class StepFunctionsStateMachineProviderPlugin(CloudFormationResourceProviderPlugin):
    name = "AWS::StepFunctions::StateMachine"

    def __init__(self):
        self.factory: Optional[Type[ResourceProvider]] = None

    def load(self):
        from localstack.services.stepfunctions.resource_providers.aws_stepfunctions_statemachine import (
            StepFunctionsStateMachineProvider,
        )

        self.factory = StepFunctionsStateMachineProvider
