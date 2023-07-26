import json
from abc import abstractmethod

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskFailedEventDetails,
    TaskScheduledEventDetails,
    TaskStartedEventDetails,
    TaskSubmittedEventDetails,
    TaskSucceededEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import (
    CallbackOutcomeFailure,
    CallbackOutcomeFailureError,
    CallbackOutcomeSuccess,
    CallbackTimeoutError,
    HeartbeatEndpoint,
    HeartbeatTimeoutError,
)
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

        # With Timeouts-only definition:
        if not self.heartbeat:
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()
            # Although the timeout is handled already be the superclass (ExecutionState),
            # the timeout value is specified here too, to allo this child process to terminate earlier even if
            # discarded by the main process.
            # Note: although this is the same timeout value, this can only decay strictly after the first timeout
            #       started as it is invoked strictly later.
            outcome = callback_endpoint.wait(timeout=timeout_seconds)
        else:
            self.heartbeat.eval(env=env)
            heartbeat_seconds = env.stack.pop()
            heartbeat_endpoint: HeartbeatEndpoint = callback_endpoint.setup_heartbeat_endpoint(
                heartbeat_seconds=heartbeat_seconds
            )

            outcome = None
            while (
                env.is_running() and outcome is None
            ):  # Until subprocess hasn't timed out or result wasn't received.
                received = heartbeat_endpoint.clear_and_wait()
                if not received and env.is_running():  # Heartbeat timed out.
                    raise HeartbeatTimeoutError()
                outcome = callback_endpoint.get_outcome()

        if outcome is None:
            raise CallbackTimeoutError()
        if isinstance(outcome, CallbackOutcomeSuccess):
            outcome_output = json.loads(outcome.output)
            env.stack.append(outcome_output)
        elif isinstance(outcome, CallbackOutcomeFailure):
            raise CallbackOutcomeFailureError(callback_outcome_failure=outcome)
        else:
            raise NotImplementedError(f"Unsupported CallbackOutcome type '{type(outcome)}'.")

    def _sync(self, env: Environment) -> None:
        raise RuntimeError(
            f"Unsupported .sync callback procedure in resource {self.resource.resource_arn}"
        )

    def _is_condition(self):
        return self.resource.condition is not None

    def _get_callback_outcome_failure_event(self, ex: CallbackOutcomeFailureError) -> FailureEvent:
        callback_outcome_failure: CallbackOutcomeFailure = ex.callback_outcome_failure
        error: str = callback_outcome_failure.error
        return FailureEvent(
            error_name=CustomErrorName(error_name=callback_outcome_failure.error),
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(
                taskFailedEventDetails=TaskFailedEventDetails(
                    resourceType=self._get_sfn_resource_type(),
                    resource=self._get_sfn_resource(),
                    error=error,
                    cause=callback_outcome_failure.cause,
                )
            ),
        )

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, CallbackOutcomeFailureError):
            return self._get_callback_outcome_failure_event(ex=ex)
        return super()._from_error(env=env, ex=ex)

    def _eval_execution(self, env: Environment) -> None:
        parameters = self._eval_parameters(env=env)
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

        normalised_parameters = self._normalised_parameters_bindings(parameters)
        self._eval_service_task(env=env, parameters=normalised_parameters)

        if self._is_condition():
            output = env.stack[-1]
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
                case ResourceCondition.Sync:
                    self._sync(env=env)
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
