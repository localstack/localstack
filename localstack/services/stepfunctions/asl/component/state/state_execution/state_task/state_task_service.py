from __future__ import annotations

import abc

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.resource import (
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)


# TODO: improve on factory constructor (don't use SubtypeManager)
class StateTaskService(StateTask, abc.ABC):
    resource: ServiceResource

    @classmethod
    def for_service(cls, service_name: str) -> StateTaskService:
        match service_name:
            case "aws-sdk":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service_aws_sdk import (
                    StateTaskServiceAwsSdk,
                )

                return StateTaskServiceAwsSdk()
            case "lambda":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service_lambda import (
                    StateTaskServiceLambda,
                )

                return StateTaskServiceLambda()
            case unknown:
                raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
