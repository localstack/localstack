import json

from botocore.exceptions import ClientError

from localstack.aws.api.stepfunctions import (
    ActivityDoesNotExist,
    ActivityFailedEventDetails,
    ActivityScheduledEventDetails,
    ActivityStartedEventDetails,
    ActivitySucceededEventDetails,
    ActivityTimedOutEventDetails,
    ExecutionFailedEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import (
    EvalTimeoutError,
    TimeoutSeconds,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ActivityResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.eval.callback.callback import (
    ActivityTaskStartOutcome,
    CallbackOutcomeFailure,
    CallbackOutcomeFailureError,
    CallbackOutcomeSuccess,
    CallbackTimeoutError,
    HeartbeatTimeoutError,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class StateTaskActivity(StateTask):
    resource: ActivityResource

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, TimeoutError):
            return FailureEvent(
                env=env,
                error_name=StatesErrorName(typ=StatesErrorNameType.StatesTimeout),
                event_type=HistoryEventType.ActivityTimedOut,
                event_details=EventDetails(
                    activityTimedOutEventDetails=ActivityTimedOutEventDetails(
                        error=StatesErrorNameType.StatesTimeout.to_name(),
                    )
                ),
            )

        if isinstance(ex, FailureEventException):
            raise ex

        if isinstance(ex, CallbackOutcomeFailureError):
            error = ex.callback_outcome_failure.error
            error_name = CustomErrorName(error)
            cause = ex.callback_outcome_failure.cause
        else:
            error_name = StatesErrorName(typ=StatesErrorNameType.StatesRuntime)
            error = error_name.error_name
            cause = ex.response["Error"]["Message"] if isinstance(ex, ClientError) else str(ex)
        return FailureEvent(
            env=env,
            error_name=error_name,
            event_type=HistoryEventType.ActivityFailed,
            event_details=EventDetails(
                activityFailedEventDetails=ActivityFailedEventDetails(error=error, cause=cause)
            ),
        )

    def _eval_parameters(self, env: Environment) -> dict:
        if self.parargs:
            self.parargs.eval(env=env)
        activity_input = env.stack.pop()
        return activity_input

    def _eval_execution(self, env: Environment) -> None:
        # Compute the task input.
        activity_task_input = self._eval_parameters(env=env)
        if not isinstance(activity_task_input, str):
            activity_task_input = to_json_str(activity_task_input)

        # Compute the timeout and heartbeat for this task.
        timeout_seconds = TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS

        if not self.timeout.is_default_value():
            self.timeout.eval(env=env)
            timeout_seconds = env.stack.pop()

        heartbeat_seconds = None
        if self.heartbeat:
            self.heartbeat.eval(env=env)
            heartbeat_seconds = env.stack.pop()

        # Publish the activity task on the callback manager.
        task_token = env.states.context_object.update_task_token()
        try:
            callback_endpoint = env.callback_pool_manager.add_activity_task(
                callback_id=task_token,
                activity_arn=self.resource.resource_arn,
                activity_input=activity_task_input,
            )
        except ActivityDoesNotExist:
            failure_event = FailureEvent(
                env=env,
                error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                event_type=HistoryEventType.ExecutionFailed,
                event_details=EventDetails(
                    executionFailedEventDetails=ExecutionFailedEventDetails(
                        error=StatesErrorNameType.StatesRuntime.to_name(),
                        cause="The activity activity_arn does not exist.",
                    )
                ),
            )
            raise FailureEventException(failure_event=failure_event)

        # Log the task is scheduled.
        scheduled_event_details = ActivityScheduledEventDetails(
            resource=self.resource.resource_arn,
            input=activity_task_input,
            inputDetails=HistoryEventExecutionDataDetails(
                truncated=False  # Always False for api calls.
            ),
        )
        if timeout_seconds != TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS:
            scheduled_event_details["timeoutInSeconds"] = timeout_seconds
        if heartbeat_seconds is not None:
            scheduled_event_details["heartbeatInSeconds"] = heartbeat_seconds
        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.ActivityScheduled,
            event_details=EventDetails(activityScheduledEventDetails=scheduled_event_details),
        )

        # Await for the task to be sampled with timeout.
        activity_task_start_endpoint = callback_endpoint.get_activity_task_start_endpoint()
        task_start_outcome = activity_task_start_endpoint.wait(timeout_seconds=timeout_seconds)
        # Log the task was sampled or timeout error if not.
        if isinstance(task_start_outcome, ActivityTaskStartOutcome):
            started_event_details = ActivityStartedEventDetails()
            if task_start_outcome.worker_name is not None:
                started_event_details["workerName"] = task_start_outcome.worker_name
            env.event_manager.add_event(
                context=env.event_history_context,
                event_type=HistoryEventType.ActivityStarted,
                event_details=EventDetails(activityStartedEventDetails=started_event_details),
            )
        else:
            raise EvalTimeoutError()

        # Await for the task outcome, with a heartbeat or timeout strategy.
        outcome = None
        if heartbeat_seconds is None:
            # Total timeout is already handled upstream. Here we specify a timeout to allow this child operation to
            # terminate gracefully sooner. This is why we don't compute the residual outcome.
            outcome = callback_endpoint.wait(timeout=timeout_seconds)
        else:
            heartbeat_endpoint = callback_endpoint.setup_heartbeat_endpoint(
                heartbeat_seconds=heartbeat_seconds
            )
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

        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.ActivitySucceeded,
            event_details=EventDetails(
                activitySucceededEventDetails=ActivitySucceededEventDetails(
                    output=outcome.output,
                    outputDetails=HistoryEventExecutionDataDetails(
                        truncated=False  # Always False for api calls.
                    ),
                )
            ),
        )
