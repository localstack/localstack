from __future__ import annotations

import abc

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


# TODO: improve on factory constructor (don't use SubtypeManager)
class StateTaskService(StateTask, abc.ABC):
    resource: ServiceResource

    def _get_resource_type(self) -> str:
        return self.resource.service_name

    def _eval_parameters(self, env: Environment) -> dict:
        parameters = dict()
        if self.parameters:
            self.parameters.eval(env=env)
            env_parameters = env.stack.pop()
            parameters.update(env_parameters)
        return parameters

    @classmethod
    def for_service(cls, service_name: str) -> StateTaskService:
        match service_name:
            case "aws-sdk":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_aws_sdk import (
                    StateTaskServiceAwsSdk,
                )

                return StateTaskServiceAwsSdk()
            case "lambda":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_lambda import (
                    StateTaskServiceLambda,
                )

                return StateTaskServiceLambda()
            case "sqs":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sqs import (
                    StateTaskServiceSqs,
                )

                return StateTaskServiceSqs()

            case unknown:
                raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
