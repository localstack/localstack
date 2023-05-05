import abc
import logging
from typing import Optional

from localstack.aws.api.stepfunctions import (
    ExecutionFailedEventDetails,
    HistoryEventType,
    TaskFailedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import (
    CatchOutcome,
    CatchOutcomeNotCaught,
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
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails

LOG = logging.getLogger(__name__)


class ExecutionState(CommonStateField, abc.ABC):
    def __init__(
        self,
        state_entered_event_type: HistoryEventType,
        state_exited_event_type: Optional[HistoryEventType],
    ):
        super().__init__(
            state_entered_event_type=state_entered_event_type,
            state_exited_event_type=state_exited_event_type,
        )
        # ResultPath (Optional)
        # Specifies where (in the input) to place the results of executing the state_task that's specified in Resource.
        # The input is then filtered as specified by the OutputPath field (if present) before being used as the
        # state's output.
        self.result_path: Optional[ResultPath] = None

        # ResultSelector (Optional)
        # Pass a collection of key value pairs, where the values are static or selected from the result.
        self.result_selector: Optional[ResultSelector] = None

        # Retry (Optional)
        # An array of objects, called Retriers, that define a retry policy if the state encounters runtime errors.
        self.retry: Optional[RetryDecl] = None

        # Catch (Optional)
        # An array of objects, called Catchers, that define a fallback state. This state is executed if the state
        # encounters runtime errors and its retry policy is exhausted or isn't defined.
        self.catch: Optional[CatchDecl] = None

    def from_state_props(self, state_props: StateProps) -> None:
        super().from_state_props(state_props=state_props)
        self.result_path = state_props.get(ResultPath)
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        LOG.warning("State Task executed generic failure event reporting logic.")
        return FailureEvent(
            error_name=StatesErrorName(typ=StatesErrorNameType.StatesTaskFailed),
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(
                taskFailedEventDetails=TaskFailedEventDetails(
                    error="Unsupported Error Handling",
                    cause=str(ex),
                )
            ),
        )

    @abc.abstractmethod
    def _eval_execution(self, env: Environment) -> None:
        ...

    def _handle_retry(self, ex: Exception, env: Environment) -> None:
        failure_event: FailureEvent = self._from_error(env=env, ex=ex)
        env.stack.append(failure_event.error_name)

        self.retry.eval(env)
        res: RetryOutcome = env.stack.pop()

        match res:
            case RetryOutcome.CanRetry:
                self._eval_state(env)
            case RetryOutcome.CannotRetry:
                # TODO: error type.
                raise RuntimeError("Reached maximum Retry attempts.")
            case RetryOutcome.NoRetrier:
                raise RuntimeError(f"No Retriers when dealing with exception '{ex}'.")

    def _handle_catch(self, ex: Exception, env: Environment) -> None:
        failure_event: FailureEvent = self._from_error(env=env, ex=ex)

        env.event_history.add_event(
            hist_type_event=failure_event.event_type, event_detail=failure_event.event_details
        )

        env.stack.append(failure_event)

        self.catch.eval(env)
        res: CatchOutcome = env.stack.pop()

        if isinstance(res, CatchOutcomeNotCaught):
            self._terminate_with_event(failure_event=failure_event, env=env)

    def _handle_uncaught(self, ex: Exception, env: Environment):
        # Log state failure.
        state_failure_event = self._from_error(env=env, ex=ex)
        env.event_history.add_event(
            hist_type_event=state_failure_event.event_type,
            event_detail=state_failure_event.event_details,
        )
        self._terminate_with_event(state_failure_event, env)

    @staticmethod
    def _terminate_with_event(failure_event: FailureEvent, env: Environment) -> None:
        # Halt execution with the given failure event.
        env.set_error(
            ExecutionFailedEventDetails(**(list(failure_event.event_details.values())[0]))
        )

    def _eval_state(self, env: Environment) -> None:
        try:
            self._eval_execution(env)

            if self.result_selector:
                self.result_selector.eval(env=env)

            if self.result_path:
                self.result_path.eval(env)
            else:
                res = env.stack.pop()
                env.inp = res
        except Exception as ex:
            if self.retry:
                self._handle_retry(ex, env)
            elif self.catch:
                self._handle_catch(ex, env)
            else:
                self._handle_uncaught(ex, env)
