from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    ExecutionAbortedEventDetails,
    ExecutionSucceededEventDetails,
    HistoryEventExecutionDataDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.states import States
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.eval.programstate.program_ended import ProgramEnded
from localstack.services.stepfunctions.asl.eval.programstate.program_error import ProgramError
from localstack.services.stepfunctions.asl.eval.programstate.program_state import ProgramState
from localstack.services.stepfunctions.asl.eval.programstate.program_stopped import ProgramStopped
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class Program(EvalComponent):
    def __init__(self, start_at: StartAt, states: States, comment: Optional[Comment] = None):
        self.start_at: Final[StartAt] = start_at
        self.states: Final[States] = states
        self.comment: Final[Optional[Comment]] = comment

    def _get_state(self, state_name: str) -> CommonStateField:
        state: Optional[CommonStateField] = self.states.states.get(state_name, None)
        if state is None:
            raise ValueError(f"No such state {state}.")
        return state

    def eval(self, env: Environment) -> None:
        env.next_state_name = self.start_at.start_at_name
        super().eval(env=env)

    def _eval_body(self, env: Environment) -> None:
        while env.is_running():
            next_state: CommonStateField = self._get_state(env.next_state_name)
            next_state.eval(env)

        # TODO: error handling.
        program_state: ProgramState = env.program_state()
        if isinstance(program_state, ProgramError):
            raise Exception(program_state.error)
        elif isinstance(program_state, ProgramStopped):
            env.event_history.add_event(
                hist_type_event=HistoryEventType.ExecutionAborted,
                event_detail=EventDetails(
                    executionAbortedEventDetails=ExecutionAbortedEventDetails(
                        error=program_state.error, cause=program_state.cause
                    )
                ),
            )
        elif isinstance(program_state, ProgramEnded):
            env.event_history.add_event(
                hist_type_event=HistoryEventType.ExecutionSucceeded,
                event_detail=EventDetails(
                    executionSucceededEventDetails=ExecutionSucceededEventDetails(
                        output=to_json_str(env.inp),
                        outputDetails=HistoryEventExecutionDataDetails(
                            truncated=False
                        ),  # Always False for api calls.
                    )
                ),
            )
