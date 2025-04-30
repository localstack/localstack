import abc
import json
import threading
import time
from typing import Any, Callable, Final, Optional

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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    StateCredentials,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceCondition,
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import (
    CallbackEndpoint,
    CallbackOutcome,
    CallbackOutcomeFailure,
    CallbackOutcomeFailureError,
    CallbackOutcomeSuccess,
    CallbackOutcomeTimedOut,
    CallbackTimeoutError,
    HeartbeatEndpoint,
    HeartbeatTimedOut,
    HeartbeatTimeoutError,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.threads import TMP_THREADS

# TODO: consider implementing a polling pattern similar to that observable from AWS:
# https://repost.aws/questions/QUFFlHcbvIQFe-bS3RAi7TWA/a-glue-job-in-a-step-function-is-taking-so-long-to-continue-the-next-step
_DELAY_SECONDS_SYNC_CONDITION_CHECK: Final[float] = 0.5


class StateTaskServiceCallback(StateTaskService, abc.ABC):
    _supported_integration_patterns: Final[set[ResourceCondition]]

    def __init__(self, supported_integration_patterns: set[ResourceCondition]):
        super().__init__()
        self._supported_integration_patterns = supported_integration_patterns

    def _get_sfn_resource(self) -> str:
        resource = super()._get_sfn_resource()
        if self.resource.condition is not None:
            resource += f".{self.resource.condition}"
        return resource

    def _build_sync_resolver(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ) -> Callable[[], Optional[Any]]:
        raise RuntimeError(
            f"Unsupported .sync callback procedure in resource {self.resource.resource_arn}"
        )

    def _build_sync2_resolver(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ) -> Callable[[], Optional[Any]]:
        raise RuntimeError(
            f"Unsupported .sync2 callback procedure in resource {self.resource.resource_arn}"
        )

    def _eval_wait_for_task_token(
        self,
        env: Environment,
        timeout_seconds: int,
        callback_endpoint: CallbackEndpoint,
        heartbeat_endpoint: Optional[HeartbeatEndpoint],
    ) -> CallbackOutcome:
        outcome: Optional[CallbackOutcome]
        if heartbeat_endpoint is not None:
            outcome = self._wait_for_task_token_heartbeat(
                env, callback_endpoint, heartbeat_endpoint
            )
        else:
            outcome = self._wait_for_task_token_timeout(timeout_seconds, callback_endpoint)
        if outcome is None:
            return CallbackOutcomeTimedOut(callback_id=callback_endpoint.callback_id)
        return outcome

    def _eval_sync(
        self,
        env: Environment,
        sync_resolver: Callable[[], Optional[Any]],
        timeout_seconds: Optional[int],
        callback_endpoint: Optional[CallbackEndpoint],
        heartbeat_endpoint: Optional[HeartbeatEndpoint],
    ) -> CallbackOutcome | Any:
        callback_output: Optional[CallbackOutcome] = None

        # Listen for WaitForTaskToken signals if an endpoint is provided.
        if callback_endpoint is not None:

            def _local_update_wait_for_task_token():
                nonlocal callback_output
                callback_output = self._eval_wait_for_task_token(
                    env=env,
                    timeout_seconds=timeout_seconds,
                    callback_endpoint=callback_endpoint,
                    heartbeat_endpoint=heartbeat_endpoint,
                )

            thread_wait_for_task_token = threading.Thread(
                target=_local_update_wait_for_task_token,
                name=f"WaitForTaskToken_SyncTask_{self.resource.resource_arn}",
                daemon=True,
            )
            TMP_THREADS.append(thread_wait_for_task_token)
            thread_wait_for_task_token.start()
            # Note: the stopping of this worker thread is handled indirectly through the state of env.
            #       an exception in this thread will invalidate env, and therefore the worker thread.
            #       hence why here there are no explicit stopping logic for thread_wait_for_task_token.

        sync_result: Optional[Any] = None
        while env.is_running():
            sync_result = sync_resolver()
            if callback_output or sync_result:
                break
            else:
                time.sleep(_DELAY_SECONDS_SYNC_CONDITION_CHECK)

        return callback_output or sync_result

    def _eval_integration_pattern(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ) -> None:
        task_output = env.stack.pop()

        # Initialise the waitForTaskToken Callback endpoint for this task if supported.
        callback_endpoint: Optional[CallbackEndpoint] = None
        if ResourceCondition.WaitForTaskToken in self._supported_integration_patterns:
            callback_id = env.states.context_object.context_object_data["Task"]["Token"]
            callback_endpoint = env.callback_pool_manager.get(callback_id)

        # Setup resources for timeout control.
        self.timeout.eval(env=env)
        timeout_seconds = env.stack.pop()

        # Setup resources for heartbeat workloads if necessary.
        heartbeat_endpoint: Optional[HeartbeatEndpoint] = None
        if self.heartbeat:
            self.heartbeat.eval(env=env)
            heartbeat_seconds = env.stack.pop()
            heartbeat_endpoint: HeartbeatEndpoint = callback_endpoint.setup_heartbeat_endpoint(
                heartbeat_seconds=heartbeat_seconds
            )

        # Collect the output of the integration pattern.
        outcome: CallbackOutcome | Any
        try:
            if self.resource.condition == ResourceCondition.WaitForTaskToken:
                outcome = self._eval_wait_for_task_token(
                    env=env,
                    timeout_seconds=timeout_seconds,
                    callback_endpoint=callback_endpoint,
                    heartbeat_endpoint=heartbeat_endpoint,
                )
            else:
                # Sync operations require the task output as input.
                env.stack.append(task_output)
                if self.resource.condition == ResourceCondition.Sync:
                    sync_resolver = self._build_sync_resolver(
                        env=env,
                        resource_runtime_part=resource_runtime_part,
                        normalised_parameters=normalised_parameters,
                        state_credentials=state_credentials,
                    )
                else:
                    # The condition checks about the resource's condition is exhaustive leaving
                    # only Sync2 ResourceCondition types in this block.
                    sync_resolver = self._build_sync2_resolver(
                        env=env,
                        resource_runtime_part=resource_runtime_part,
                        normalised_parameters=normalised_parameters,
                        state_credentials=state_credentials,
                    )

                outcome = self._eval_sync(
                    env=env,
                    timeout_seconds=timeout_seconds,
                    callback_endpoint=callback_endpoint,
                    heartbeat_endpoint=heartbeat_endpoint,
                    sync_resolver=sync_resolver,
                )
        except Exception as integration_exception:
            outcome = integration_exception
        finally:
            # Now that the outcome is collected or the exception is about to be passed upstream, and the process has
            # finished, ensure all waiting # threads on this endpoint (or task) will stop. This is in an effort to
            # release resources sooner than when these would eventually synchronise with the updated environment
            # state of this task.
            callback_endpoint.interrupt_all()

        # Handle Callback outcome types.
        if isinstance(outcome, CallbackOutcomeTimedOut):
            raise CallbackTimeoutError()
        elif isinstance(outcome, HeartbeatTimedOut):
            raise HeartbeatTimeoutError()
        elif isinstance(outcome, CallbackOutcomeFailure):
            raise CallbackOutcomeFailureError(callback_outcome_failure=outcome)
        elif isinstance(outcome, CallbackOutcomeSuccess):
            outcome_output = json.loads(outcome.output)
            env.stack.append(outcome_output)
        # Pass evaluation exception upstream for error handling.
        elif isinstance(outcome, Exception):
            raise outcome
        # Otherwise the outcome is the result of the integration pattern (sync, sync2)
        # therefore push it onto the evaluation stack for the next operations.
        else:
            env.stack.append(outcome)

    def _wait_for_task_token_timeout(  # noqa
        self,
        timeout_seconds: int,
        callback_endpoint: CallbackEndpoint,
    ) -> Optional[CallbackOutcome]:
        # Awaits a callback notification and returns the outcome received.
        # If the operation times out or is interrupted it returns None.

        # Although the timeout is handled already be the superclass (ExecutionState),
        # the timeout value is specified here too, to allow this child process to terminate earlier even if
        # discarded by the main process.
        # Note: although this is the same timeout value, this can only decay strictly after the first timeout
        #       started as it is invoked strictly later.
        outcome: Optional[CallbackOutcome] = callback_endpoint.wait(timeout=timeout_seconds)
        return outcome

    def _wait_for_task_token_heartbeat(  # noqa
        self,
        env: Environment,
        callback_endpoint: CallbackEndpoint,
        heartbeat_endpoint: HeartbeatEndpoint,
    ) -> Optional[CallbackOutcome]:
        outcome = None
        while (
            env.is_running()
            and outcome
            is None  # Note: the lifetime of this environment is this task's not the entire state machine program.
        ):  # Until subprocess hasn't timed out or result wasn't received.
            received = heartbeat_endpoint.clear_and_wait()
            if not received and env.is_running():  # Heartbeat timed out.
                outcome = HeartbeatTimedOut()
            else:
                outcome = callback_endpoint.get_outcome()
        return outcome

    def _assert_integration_pattern_is_supported(self):
        integration_pattern = self.resource.condition
        if integration_pattern not in self._supported_integration_patterns:
            raise RuntimeError(
                f"Unsupported {integration_pattern} callback procedure in resource {self.resource.resource_arn}"
            )

    def _is_integration_pattern(self):
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
        # Generate a TaskToken uuid within the context object, if this task resources has a callback condition.
        # https://docs.aws.amazon.com/step-functions/latest/dg/connect-to-resource.html#connect-wait-token
        if (
            self._is_integration_pattern()
            and ResourceCondition.WaitForTaskToken in self._supported_integration_patterns
        ):
            self._assert_integration_pattern_is_supported()
            task_token = env.states.context_object.update_task_token()
            env.callback_pool_manager.add(task_token)

        super()._eval_body(env=env)

        # Ensure the TaskToken field is reset, as this is only available during waitForTaskToken task evaluations.
        env.states.context_object.context_object_data.pop("Task", None)

    def _after_eval_execution(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
        state_credentials: StateCredentials,
    ) -> None:
        # TODO: In Mock mode, when simulating a failure, the mock response is handled by
        # super()._eval_execution, so this block is never executed. Consequently, the
        # "TaskSubmitted" event isn’t recorded in the event history.
        if self._is_integration_pattern():
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
            if not env.is_mocked_mode():
                self._eval_integration_pattern(
                    env=env,
                    resource_runtime_part=resource_runtime_part,
                    normalised_parameters=normalised_parameters,
                    state_credentials=state_credentials,
                )
        super()._after_eval_execution(
            env=env,
            resource_runtime_part=resource_runtime_part,
            normalised_parameters=normalised_parameters,
            state_credentials=state_credentials,
        )
