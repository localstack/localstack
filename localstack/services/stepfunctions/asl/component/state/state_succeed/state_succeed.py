from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_continue_with import (
    ContinueWithSuccess,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StateSucceed(CommonStateField):
    def __init__(self):
        super().__init__(
            state_entered_event_type=HistoryEventType.SucceedStateEntered,
            state_exited_event_type=HistoryEventType.SucceedStateExited,
        )

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateSucceed, self).from_state_props(state_props)
        # TODO: assert all other fields are undefined?

        # No Next or End field: Succeed states are terminal states.
        if state_props.get(Next) or state_props.get(End):
            raise ValueError(
                f"No Next or End field: Succeed states are terminal states: with state '{self}'."
            )
        self.continue_with = ContinueWithSuccess()

    def _eval_state(self, env: Environment) -> None:
        pass
