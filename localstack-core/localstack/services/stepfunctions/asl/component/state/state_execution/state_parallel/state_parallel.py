import copy

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import CatchOutcome
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
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
        super().__init__(
            state_entered_event_type=HistoryEventType.ParallelStateEntered,
            state_exited_event_type=HistoryEventType.ParallelStateExited,
        )

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateParallel, self).from_state_props(state_props)
        self.branches = state_props.get(
            typ=BranchesDecl,
            raise_on_missing=ValueError(f"Missing Branches definition in props '{state_props}'."),
        )

    def _eval_execution(self, env: Environment) -> None:
        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.ParallelStateStarted,
        )
        self.branches.eval(env)
        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.ParallelStateSucceeded,
            update_source_event_id=False,
        )

    def _eval_state(self, env: Environment) -> None:
        # Initialise the retry counter for execution states.
        env.context_object_manager.context_object["State"]["RetryCount"] = 0

        # Cache the input, so it can be resubmitted in case of failure.
        input_value = copy.deepcopy(env.stack.pop())

        # Attempt to evaluate the state's logic through until it's successful, caught, or retries have run out.
        while True:
            try:
                env.stack.append(input_value)
                self._evaluate_with_timeout(env)
                break
            except FailureEventException as failure_event_ex:
                failure_event: FailureEvent = failure_event_ex.failure_event

                if self.retry is not None:
                    retry_outcome: RetryOutcome = self._handle_retry(
                        env=env, failure_event=failure_event
                    )
                    if retry_outcome == RetryOutcome.CanRetry:
                        continue

                env.event_manager.add_event(
                    context=env.event_history_context,
                    event_type=HistoryEventType.ParallelStateFailed,
                )

                if self.catch is not None:
                    catch_outcome: CatchOutcome = self._handle_catch(
                        env=env, failure_event=failure_event
                    )
                    if catch_outcome == CatchOutcome.Caught:
                        break

                self._handle_uncaught(env=env, failure_event=failure_event)
