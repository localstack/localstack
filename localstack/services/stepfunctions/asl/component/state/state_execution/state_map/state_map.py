import json
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
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.item_processor import (
    ItemProcessor,
    ItemProcessorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator import (
    Iterator,
    IteratorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class StateMap(ExecutionState):
    items_path: ItemsPath
    iteration_component: IterationComponent
    item_selector: Optional[ItemSelector]
    parameters: Optional[Parameters]
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
        self.items_path = state_props.get(ItemsPath) or ItemsPath()
        self.item_selector = state_props.get(ItemSelector)
        self.parameters = state_props.get(Parameters)
        self.max_concurrency = state_props.get(MaxConcurrency) or MaxConcurrency()
        self.result_path = state_props.get(ResultPath)
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)

        item_processor = state_props.get(ItemProcessor)
        iterator = state_props.get(Iterator)
        if item_processor and iterator:
            raise ValueError(
                f"Duplicate ItemProcessor/Iterator definitions in props '{state_props}'."
            )
        self.iteration_component = item_processor or iterator

        # TODO: error if parameters and itemselector both declared?

        if not self.iteration_component:
            raise ValueError(f"Missing ItemProcessor/Iterator definition in props '{state_props}'.")

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

        event_details = None
        if isinstance(self.iteration_component, Iterator) and isinstance(ex, FailureEventException):
            event_details = EventDetails(
                executionFailedEventDetails=ex.get_execution_failed_event_details()
            )

        failure_event = FailureEvent(
            error_name=CustomErrorName(HistoryEventType.MapStateFailed),
            event_type=HistoryEventType.MapStateFailed,
            event_details=event_details,
        )

        self._terminate_with_event(failure_event, env)

    def _eval_execution(self, env: Environment) -> None:
        self.items_path.eval(env)
        input_items: list[json] = env.stack.pop()

        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapStateStarted,
            event_detail=EventDetails(
                mapStateStartedEventDetails=MapStateStartedEventDetails(length=len(input_items))
            ),
        )

        if isinstance(self.iteration_component, ItemProcessor):
            eval_input = ItemProcessorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                item_selector=self.item_selector,
            )
        elif isinstance(self.iteration_component, Iterator):
            eval_input = IteratorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                parameters=self.parameters,
            )
        else:
            raise RuntimeError(
                f"Unknown iteration component of type '{type(self.iteration_component)}' '{self.iteration_component}'."
            )

        env.stack.append(eval_input)
        self.iteration_component.eval(env)

        env.event_history.add_event(
            hist_type_event=HistoryEventType.MapStateSucceeded,
        )
