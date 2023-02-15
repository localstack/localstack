from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_parallel.branches_decl import (
    BranchesDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment


class StateParallel(ExecutionState):
    # Branches (Required)
    # An array of objects that specify state machines to execute in state_parallel. Each such state
    # machine object must have fields named States and StartAt, whose meanings are exactly
    # like those in the top level of a state machine.
    branches: BranchesDecl

    def __init__(self):
        super(StateParallel).__init__(
            state_entered_event_type=HistoryEventType.ParallelStateExited,
            state_exited_event_type=HistoryEventType.ParallelStateEntered,
        )

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateParallel, self).from_state_props(state_props)
        self.branches = state_props.get(
            typ=BranchesDecl,
            raise_on_missing=ValueError(f"Missing Branches definition in props '{state_props}'."),
        )

    def _eval_execution(self, env: Environment) -> None:
        self.branches.eval(env)
