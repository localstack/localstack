from __future__ import annotations

import abc

from localstack.aws.api.stepfunctions import HistoryEventType, TaskTimedOutEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


# TODO: improve on factory constructor (don't use SubtypeManager)
class StateTaskService(StateTask, abc.ABC):
    resource: ServiceResource

    def _get_sfn_resource(self) -> str:
        return self.resource.api_action

    def _get_sfn_resource_type(self) -> str:
        return self.resource.service_name

    def _get_timed_out_failure_event(self) -> FailureEvent:
        return FailureEvent(
            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTimeout),
            event_type=HistoryEventType.TaskTimedOut,
            event_details=EventDetails(
                taskTimedOutEventDetails=TaskTimedOutEventDetails(
                    resourceType=self._get_sfn_resource_type(),
                    resource=self._get_sfn_resource(),
                    error=StatesErrorNameType.StatesTimeout.to_name(),
                )
            ),
        )

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
            case "states":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sfn import (
                    StateTaskServiceSfn,
                )

                return StateTaskServiceSfn()

            case unknown:
                raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
