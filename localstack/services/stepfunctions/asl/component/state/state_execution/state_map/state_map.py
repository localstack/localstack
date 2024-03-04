from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType, MapStateStartedEventDetails
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import CatchOutcome
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.distributed_item_processor import (
    DistributedItemProcessor,
    DistributedItemProcessorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.inline_item_processor import (
    InlineItemProcessor,
    InlineItemProcessorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.item_processor_decl import (
    ItemProcessorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.item_processor_factory import (
    from_item_processor_decl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.distributed_iterator import (
    DistributedIterator,
    DistributedIteratorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.inline_iterator import (
    InlineIterator,
    InlineIteratorEvalInput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_decl import (
    IteratorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_factory import (
    from_iterator_decl,
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
    item_reader: Optional[ItemReader]
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
        self.item_reader = state_props.get(ItemReader)
        self.item_selector = state_props.get(ItemSelector)
        self.parameters = state_props.get(Parameters)
        self.max_concurrency = state_props.get(MaxConcurrency) or MaxConcurrency()
        self.result_path = state_props.get(ResultPath) or ResultPath(
            result_path_src=ResultPath.DEFAULT_PATH
        )
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)

        # TODO: add check for itemreader used in distributed mode only.

        iterator_decl = state_props.get(typ=IteratorDecl)
        item_processor_decl = state_props.get(typ=ItemProcessorDecl)

        if iterator_decl and item_processor_decl:
            raise ValueError("Cannot define both Iterator and ItemProcessor.")

        iteration_decl = iterator_decl or item_processor_decl
        if iteration_decl is None:
            raise ValueError(f"Missing ItemProcessor/Iterator definition in props '{state_props}'.")

        if isinstance(iteration_decl, IteratorDecl):
            self.iteration_component = from_iterator_decl(iteration_decl)
        elif isinstance(iteration_decl, ItemProcessorDecl):
            self.iteration_component = from_item_processor_decl(iteration_decl)
        else:
            raise ValueError(f"Unknown value for IteratorDecl '{iteration_decl}'.")

    def _eval_execution(self, env: Environment) -> None:
        self.items_path.eval(env)
        if self.item_reader:
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.MapStateStarted,
                event_detail=EventDetails(
                    mapStateStartedEventDetails=MapStateStartedEventDetails(length=0)
                ),
            )
            input_items = None
        else:
            input_items = env.stack.pop()
            env.event_history.add_event(
                context=env.event_history_context,
                hist_type_event=HistoryEventType.MapStateStarted,
                event_detail=EventDetails(
                    mapStateStartedEventDetails=MapStateStartedEventDetails(length=len(input_items))
                ),
            )

        if isinstance(self.iteration_component, InlineIterator):
            eval_input = InlineIteratorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                parameters=self.parameters,
                item_selector=self.item_selector,
            )
        elif isinstance(self.iteration_component, DistributedIterator):
            eval_input = DistributedIteratorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                parameters=self.parameters,
                item_selector=self.item_selector,
                item_reader=self.item_reader,
            )
        elif isinstance(self.iteration_component, InlineItemProcessor):
            eval_input = InlineItemProcessorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                item_selector=self.item_selector,
                parameters=self.parameters,
            )
        elif isinstance(self.iteration_component, DistributedItemProcessor):
            eval_input = DistributedItemProcessorEvalInput(
                state_name=self.name,
                max_concurrency=self.max_concurrency.num,
                input_items=input_items,
                item_reader=self.item_reader,
                item_selector=self.item_selector,
                parameters=self.parameters,
            )
        else:
            raise RuntimeError(
                f"Unknown iteration component of type '{type(self.iteration_component)}' '{self.iteration_component}'."
            )

        env.stack.append(eval_input)
        self.iteration_component.eval(env)

        env.event_history.add_event(
            context=env.event_history_context,
            hist_type_event=HistoryEventType.MapStateSucceeded,
            update_source_event_id=False,
        )

    def _eval_state(self, env: Environment) -> None:
        # Initialise the retry counter for execution states.
        env.context_object_manager.context_object["State"]["RetryCount"] = 0

        # Attempt to evaluate the state's logic through until it's successful, caught, or retries have run out.
        while True:
            try:
                self._evaluate_with_timeout(env)
                break
            except Exception as ex:
                failure_event: FailureEvent = self._from_error(env=env, ex=ex)

                if self.retry:
                    retry_outcome: RetryOutcome = self._handle_retry(
                        env=env, failure_event=failure_event
                    )
                    if retry_outcome == RetryOutcome.CanRetry:
                        continue

                env.event_history.add_event(
                    context=env.event_history_context,
                    hist_type_event=HistoryEventType.MapStateFailed,
                )

                if self.catch:
                    catch_outcome: CatchOutcome = self._handle_catch(
                        env=env, failure_event=failure_event
                    )
                    if catch_outcome == CatchOutcome.Caught:
                        break

                self._handle_uncaught(env=env, failure_event=failure_event)
