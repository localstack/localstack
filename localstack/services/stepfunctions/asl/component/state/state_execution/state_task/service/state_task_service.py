from __future__ import annotations

import abc

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSucceededEventDetails,
    TaskTimedOutEventDetails,
)
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
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


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

    @abc.abstractmethod
    def _eval_service_task(self, env: Environment, parameters: dict):
        ...

    def _before_eval_execution(self, env: Environment, parameters: dict) -> None:
        parameters_str = to_json_str(parameters)

        scheduled_event_details = TaskScheduledEventDetails(
            resource=self._get_sfn_resource(),
            resourceType=self._get_sfn_resource_type(),
            region=self.resource.region,
            parameters=parameters_str,
        )
        if not self.timeout.is_default_value():
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()
            scheduled_event_details["timeoutInSeconds"] = timeout_seconds
        if self.heartbeat is not None:
            self.heartbeat.eval(env=env)
            heartbeat_seconds = env.stack.pop()
            scheduled_event_details["heartbeatInSeconds"] = heartbeat_seconds
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskScheduled,
            event_detail=EventDetails(taskScheduledEventDetails=scheduled_event_details),
        )

        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskStarted,
            event_detail=EventDetails(
                taskStartedEventDetails=TaskStartedEventDetails(
                    resource=self._get_sfn_resource(), resourceType=self._get_sfn_resource_type()
                )
            ),
        )

    def _after_eval_execution(self, env: Environment) -> None:
        output = env.stack[-1]
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskSucceeded,
            event_detail=EventDetails(
                taskSucceededEventDetails=TaskSucceededEventDetails(
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                    output=to_json_str(output),
                    outputDetails=HistoryEventExecutionDataDetails(truncated=False),
                )
            ),
        )

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)
        self._before_eval_execution(env=env, parameters=parameters)

        normalised_parameters = self._normalised_parameters_bindings(parameters)
        self._eval_service_task(env=env, parameters=normalised_parameters)

        self._after_eval_execution(env=env)

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
            case "dynamodb":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_dynamodb import (
                    StateTaskServiceDynamoDB,
                )

                return StateTaskServiceDynamoDB()
            case "apigateway":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_api_gateway import (
                    StateTaskServiceApiGateway,
                )

                return StateTaskServiceApiGateway()
            case "sns":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_sns import (
                    StateTaskServiceSns,
                )

                return StateTaskServiceSns()
            case "events":
                from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_events import (
                    StateTaskServiceEvents,
                )

                return StateTaskServiceEvents()

            case unknown:
                raise NotImplementedError(f"Unsupported service: '{unknown}'.")  # noqa
