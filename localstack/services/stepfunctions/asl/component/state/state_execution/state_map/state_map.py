from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType, MapStateStartedEventDetails
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import (
    CatchOutcome,
    CatchOutcomeNotCaught,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.itemprocessor.item_processor import (
    ItemProcessor,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class StateMap(ExecutionState):
    item_processor: ItemProcessor

    items_path: ItemsPath
    # item_selector: ItemSelector  # TODO
    max_concurrency: MaxConcurrency
    result_path: Optional[ResultPath]
    result_selector: ResultSelector
    retry: Optional[RetryDecl]
    catch: Optional[CatchDecl]

    def __init__(self):
        super(StateMap, self).__init__(
            state_entered_event_type=HistoryEventType.MapStateEntered,
            state_exited_event_type=HistoryEventType.MapStateExited,
        )

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateMap, self).from_state_props(state_props)
        self.item_processor = state_props.get(ItemProcessor)
        self.items_path = state_props.get(ItemsPath) or ItemsPath()
        self.max_concurrency = state_props.get(MaxConcurrency) or MaxConcurrency()
        self.result_path = state_props.get(ResultPath)
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)

        if not self.item_processor:
            raise ValueError(f"Missing ItemProcessor definition in props '{state_props}'.")

    def _handle_retry(self, ex: Exception, env: Environment) -> None:
        failure_event: FailureEvent = self._from_error(env=env, ex=ex)
        env.stack.append(failure_event.error_name)

        self.retry.eval(env)
        res: RetryOutcome = env.stack.pop()

        match res:
            case RetryOutcome.CanRetry:
                self._eval_state(env)
            case _:
                env.event_history.add_event(hist_type_event=HistoryEventType.MapStateFailed)
                self._terminate_with_event(failure_event=failure_event, env=env)

    def _handle_catch(self, ex: Exception, env: Environment) -> None:
        env.event_history.add_event(hist_type_event=HistoryEventType.MapStateFailed)

        failure_event: FailureEvent = self._from_error(env=env, ex=ex)

        env.stack.append(failure_event)

        self.catch.eval(env)
        res: CatchOutcome = env.stack.pop()

        if isinstance(res, CatchOutcomeNotCaught):
            self._terminate_with_event(failure_event=failure_event, env=env)

    def _handle_uncaught(self, ex: Exception, env: Environment):
        env.event_history.add_event(hist_type_event=HistoryEventType.MapStateFailed)
        failure_event = FailureEvent(
            error_name=CustomErrorName(HistoryEventType.MapStateFailed),
            event_type=HistoryEventType.MapStateFailed,
        )
        self._terminate_with_event(failure_event, env)

    def _eval_execution(self, env: Environment) -> None:
        self.items_path.eval(env)
        input_list = env.stack.pop()

        input_list_len = len(input_list)
        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapStateStarted,
            event_detail=EventDetails(
                mapStateStartedEventDetails=MapStateStartedEventDetails(length=input_list_len)
            ),
        )

        env.stack.append(self.name)
        env.stack.append(self.max_concurrency.num)
        env.stack.append(input_list)

        self.item_processor.eval(env)
        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapStateSucceeded,
        )
