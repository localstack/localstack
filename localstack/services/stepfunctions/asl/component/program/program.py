import logging
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    ExecutionAbortedEventDetails,
    ExecutionFailedEventDetails,
    ExecutionSucceededEventDetails,
    ExecutionTimedOutEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import TimeoutSeconds
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.program_state import (
    ProgramEnded,
    ProgramError,
    ProgramState,
    ProgramStopped,
    ProgramTimedOut,
)
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.threads import TMP_THREADS

LOG = logging.getLogger(__name__)


class Program(EvalComponent):
    start_at: Final[StartAt]
    states: Final[States]
    timeout_seconds: Final[Optional[TimeoutSeconds]]
    comment: Final[Optional[Comment]]

    def __init__(
        self,
        start_at: StartAt,
        states: States,
        timeout_seconds: Optional[TimeoutSeconds],
        comment: Optional[Comment] = None,
    ):
        self.start_at = start_at
        self.states = states
        self.timeout_seconds = timeout_seconds
        self.comment = comment

    def _get_state(self, state_name: str) -> CommonStateField:
        state: Optional[CommonStateField] = self.states.states.get(state_name, None)
        if state is None:
            raise ValueError(f"No such state {state}.")
        return state

    def eval(self, env: Environment) -> None:
        timeout = self.timeout_seconds.timeout_seconds if self.timeout_seconds else None
        env.next_state_name = self.start_at.start_at_name
        worker_thread = threading.Thread(target=super().eval, args=(env,))
        TMP_THREADS.append(worker_thread)
        worker_thread.start()
        worker_thread.join(timeout=timeout)
        is_timeout = worker_thread.is_alive()
        if is_timeout:
            env.set_timed_out()

    def _eval_body(self, env: Environment) -> None:
        try:
            while env.is_running():
                next_state: CommonStateField = self._get_state(env.next_state_name)
                next_state.eval(env)
        except FailureEventException as ex:
            env.set_error(error=ex.get_execution_failed_event_details())
        except Exception as ex:
            cause = f"{type(ex)}({str(ex)})"
            LOG.error(f"Stepfunctions computation ended with exception '{cause}'.")
            env.set_error(
                ExecutionFailedEventDetails(
                    error="Internal Error", cause=f"Internal Error due to '{cause}'"
                )
            )

        # If the program is evaluating within a frames then these are not allowed to produce program termination states.
        if env.is_frame():
            return

        program_state: ProgramState = env.program_state()
        if isinstance(program_state, ProgramError):
            exec_failed_event_details = select_from_typed_dict(
                typed_dict=ExecutionFailedEventDetails, obj=program_state.error or dict()
            )
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.ExecutionFailed,
                event_detail=EventDetails(executionFailedEventDetails=exec_failed_event_details),
            )
        elif isinstance(program_state, ProgramStopped):
            env.event_history_context.source_event_id = 0
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.ExecutionAborted,
                event_detail=EventDetails(
                    executionAbortedEventDetails=ExecutionAbortedEventDetails(
                        error=program_state.error, cause=program_state.cause
                    )
                ),
            )
        elif isinstance(program_state, ProgramTimedOut):
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.ExecutionTimedOut,
                event_detail=EventDetails(
                    executionTimedOutEventDetails=ExecutionTimedOutEventDetails()
                ),
            )
        elif isinstance(program_state, ProgramEnded):
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.ExecutionSucceeded,
                event_detail=EventDetails(
                    executionSucceededEventDetails=ExecutionSucceededEventDetails(
                        output=to_json_str(env.inp, separators=(",", ":")),
                        outputDetails=HistoryEventExecutionDataDetails(
                            truncated=False  # Always False for api calls.
                        ),
                    )
                ),
            )
