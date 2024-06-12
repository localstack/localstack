import abc
import json
import time
from typing import Optional

from localstack.aws.api.stepfunctions import (
    HistoryEventExecutionDataDetails,
    HistoryEventType,
    TaskFailedEventDetails,
    TaskSubmittedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
    ResourceRuntimePart,
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


class StateTaskServiceCallback(StateTaskService, abc.ABC):
    def _get_sfn_resource(self) -> str:
        resource = super()._get_sfn_resource()
        if self.resource.condition is not None:
            resource += f".{self.resource.condition}"
        return resource

    def _wait_for_task_token(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        # Discard the state evaluation output.
        env.stack.pop()

        callback_id = env.context_object_manager.context_object["Task"]["Token"]
        callback_endpoint = env.callback_pool_manager.get(callback_id)

        # With Timeouts-only definition:
        if not self.heartbeat:
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()
            # Although the timeout is handled already be the superclass (ExecutionState),
            # the timeout value is specified here too, to allow this child process to terminate earlier even if
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

    def _sync(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        raise RuntimeError(
            f"Unsupported .sync callback procedure in resource {self.resource.resource_arn}"
        )

    def _sync2(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        raise RuntimeError(
            f"Unsupported .sync:2 callback procedure in resource {self.resource.resource_arn}"
        )

    @staticmethod
    def _throttle_sync_iteration(seconds: float = 0.5):
        # TODO: consider implementing a polling pattern similar to that observable from AWS:
        # https://repost.aws/questions/QUFFlHcbvIQFe-bS3RAi7TWA/a-glue-job-in-a-step-function-is-taking-so-long-to-continue-the-next-step
        time.sleep(seconds)

    def _is_condition(self):
        return self.resource.condition is not None

    def _get_callback_outcome_failure_event(
        self, env: Environment, ex: CallbackOutcomeFailureError
    ) -> FailureEvent:
        callback_outcome_failure: CallbackOutcomeFailure = ex.callback_outcome_failure
        error: Optional[str] = callback_outcome_failure.error
        return FailureEvent(
            env=env,
            error_name=CustomErrorName(error_name=error),
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
            return self._get_callback_outcome_failure_event(env=env, ex=ex)
        return super()._from_error(env=env, ex=ex)

    def _eval_body(self, env: Environment) -> None:
        # Generate a TaskToken uuid within the context object, if this task resources has a waitForTaskToken condition.
        # This logic provisions a TaskToken callback uuid to support waitForTaskToken workflows as described in :
        # https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token
        if self._is_condition() and self.resource.condition == ResourceCondition.WaitForTaskToken:
            task_token = env.context_object_manager.update_task_token()
            env.callback_pool_manager.add(task_token)

        super()._eval_body(env=env)

        # Ensure the TaskToken field is reset, as this is only available during waitForTaskToken task evaluations.
        env.context_object_manager.context_object.pop("Task", None)

    def _after_eval_execution(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ) -> None:
        if self._is_condition():
            output = env.stack[-1]
            env.event_manager.add_event(
                context=env.event_history_context,
                event_type=HistoryEventType.TaskSubmitted,
                event_details=EventDetails(
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
                    self._wait_for_task_token(
                        env=env,
                        resource_runtime_part=resource_runtime_part,
                        normalised_parameters=normalised_parameters,
                    )
                case ResourceCondition.Sync:
                    self._sync(
                        env=env,
                        resource_runtime_part=resource_runtime_part,
                        normalised_parameters=normalised_parameters,
                    )
                case ResourceCondition.Sync2:
                    self._sync2(
                        env=env,
                        resource_runtime_part=resource_runtime_part,
                        normalised_parameters=normalised_parameters,
                    )
                case unsupported:
                    raise NotImplementedError(f"Unsupported callback type '{unsupported}'.")

        super()._after_eval_execution(
            env=env,
            resource_runtime_part=resource_runtime_part,
            normalised_parameters=normalised_parameters,
        )
