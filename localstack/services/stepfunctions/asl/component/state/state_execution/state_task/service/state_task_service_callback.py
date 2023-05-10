import json
from abc import abstractmethod

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSubmittedEventDetails,
    TaskSucceededEventDetails,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import CallbackOutcomeSuccess
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class StateTaskServiceCallback(StateTaskService):
    def _get_sfn_resource(self) -> str:
        resource = super()._get_sfn_resource()
        if self.resource.condition is not None:
            resource += f".{self.resource.condition}"
        return resource

    @abstractmethod
    def _eval_service_task(self, env: Environment, parameters: dict):
        ...

    def _wait_for_task_token(self, env: Environment) -> None:  # noqa
        callback_id = env.context_object_manager.context_object["Task"]["Token"]
        callback_endpoint = env.callback_pool_manager.get(callback_id)
        outcome = callback_endpoint.wait()  # TODO: implement timeout.

        if isinstance(outcome, CallbackOutcomeSuccess):
            outcome_output = json.loads(outcome.output)
            env.stack.append(outcome_output)
        else:
            raise NotImplementedError(f"Unsupported Callbackoutcome type '{type(outcome)}'.")

    def _is_condition(self):
        return self.resource.condition is not None

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)
        parameters_str = to_json_str(parameters)

        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskScheduled,
            event_detail=EventDetails(
                taskScheduledEventDetails=TaskScheduledEventDetails(
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                    region=self.resource.region,
                    parameters=parameters_str,
                )
            ),
        )
        env.event_history.add_event(
            hist_type_event=HistoryEventType.TaskStarted,
            event_detail=EventDetails(
                taskStartedEventDetails=TaskStartedEventDetails(
                    resource=self._get_sfn_resource(), resourceType=self._get_sfn_resource_type()
                )
            ),
        )

        self._eval_service_task(env=env, parameters=parameters)

        if self._is_condition():
            output = env.stack.pop()
            env.event_history.add_event(
                hist_type_event=HistoryEventType.TaskSubmitted,
                event_detail=EventDetails(
                    taskSubmittedEventDetails=TaskSubmittedEventDetails(
                        resource=self._get_sfn_resource(),
                        resourceType=self._get_sfn_resource_type(),
                        output=to_json_str(output),
                        outputDetails=HistoryEventExecutionDataDetails(truncated=False),
                    )
                ),
            )
            match self.resource.condition:
                case ResourceCondition.WaitForTaskToken:
                    self._wait_for_task_token(env=env)
                case unsupported:
                    raise NotImplementedError(f"Unsupported callback type '{unsupported}'.")

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
