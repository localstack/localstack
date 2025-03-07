import copy
from typing import Optional

from localstack.aws.api.stepfunctions import (
    EvaluationFailedEventDetails,
    HistoryEventType,
    MapStateStartedEventDetails,
)
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.catch.catch_outcome import CatchOutcome
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
from localstack.services.stepfunctions.asl.component.common.parargs import Parameters, Parargs
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
from localstack.services.stepfunctions.asl.component.common.retry.retry_outcome import RetryOutcome
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    JSONPATH_ROOT_PATH,
    StringJsonPath,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.execute_state import (
    ExecutionState,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.item_reader_decl import (
    ItemReader,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_selector import (
    ItemSelector,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.items.items import (
    Items,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.distributed_iteration_component import (
    DistributedIterationComponent,
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.map_run_record import (
    MapRunRecord,
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.label import (
    Label,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrency,
    MaxConcurrencyDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.result_writer.result_writer_decl import (
    ResultWriter,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.tolerated_failure import (
    ToleratedFailureCountDecl,
    ToleratedFailureCountInt,
    ToleratedFailurePercentage,
    ToleratedFailurePercentageDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class StateMap(ExecutionState):
    items: Optional[Items]
    items_path: Optional[ItemsPath]
    iteration_component: IterationComponent
    item_reader: Optional[ItemReader]
    item_selector: Optional[ItemSelector]
    parameters: Optional[Parameters]
    max_concurrency_decl: MaxConcurrencyDecl
    tolerated_failure_count_decl: ToleratedFailureCountDecl
    tolerated_failure_percentage_decl: ToleratedFailurePercentage
    result_path: Optional[ResultPath]
    result_selector: ResultSelector
    retry: Optional[RetryDecl]
    catch: Optional[CatchDecl]
    label: Optional[Label]
    result_writer: Optional[ResultWriter]

    def __init__(self):
        super(StateMap, self).__init__(
            state_entered_event_type=HistoryEventType.MapStateEntered,
            state_exited_event_type=HistoryEventType.MapStateExited,
        )

    def from_state_props(self, state_props: StateProps) -> None:
        super(StateMap, self).from_state_props(state_props)
        if self._is_language_query_jsonpath():
            self.items = None
            self.items_path = state_props.get(ItemsPath) or ItemsPath(
                string_sampler=StringJsonPath(JSONPATH_ROOT_PATH)
            )
        else:
            # TODO: add snapshot test to assert what missing definitions of items means for a states map
            self.items_path = None
            self.items = state_props.get(Items)
        self.item_reader = state_props.get(ItemReader)
        self.item_selector = state_props.get(ItemSelector)
        self.parameters = state_props.get(Parargs)
        self.max_concurrency_decl = state_props.get(MaxConcurrencyDecl) or MaxConcurrency()
        self.tolerated_failure_count_decl = (
            state_props.get(ToleratedFailureCountDecl) or ToleratedFailureCountInt()
        )
        self.tolerated_failure_percentage_decl = (
            state_props.get(ToleratedFailurePercentageDecl) or ToleratedFailurePercentage()
        )
        self.result_path = state_props.get(ResultPath) or ResultPath(
            result_path_src=ResultPath.DEFAULT_PATH
        )
        self.result_selector = state_props.get(ResultSelector)
        self.retry = state_props.get(RetryDecl)
        self.catch = state_props.get(CatchDecl)
        self.label = state_props.get(Label)
        self.result_writer = state_props.get(ResultWriter)

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
        self.max_concurrency_decl.eval(env=env)
        max_concurrency_num = env.stack.pop()
        label = self.label.label if self.label else None

        # Despite MaxConcurrency and Tolerance fields being state level fields, AWS StepFunctions evaluates only
        # MaxConcurrency as a state level field. In contrast, Tolerance is evaluated only after the state start
        # event but is logged with event IDs coherent with state level fields. To adhere to this quirk, an evaluation
        # frame from this point is created for the evaluation of Tolerance fields following the state start event.
        frame: Environment = env.open_frame()
        frame.states.reset(input_value=env.states.get_input())
        frame.stack = copy.deepcopy(env.stack)

        try:
            # ItemsPath in DistributedMap states is only used if a JSONinput is passed from the previous state.
            if (
                not isinstance(self.iteration_component, DistributedIterationComponent)
                or self.item_reader is None
            ):
                if self.items_path:
                    self.items_path.eval(env=env)

            if self.items:
                self.items.eval(env=env)

            if self.item_reader:
                env.event_manager.add_event(
                    context=env.event_history_context,
                    event_type=HistoryEventType.MapStateStarted,
                    event_details=EventDetails(
                        mapStateStartedEventDetails=MapStateStartedEventDetails(length=0)
                    ),
                )
                input_items = None
            else:
                input_items = env.stack.pop()
                # TODO: This should probably be raised within an Items EvalComponent
                if not isinstance(input_items, list):
                    error_name = StatesErrorName(typ=StatesErrorNameType.StatesQueryEvaluationError)
                    failure_event = FailureEvent(
                        env=env,
                        error_name=error_name,
                        event_type=HistoryEventType.EvaluationFailed,
                        event_details=EventDetails(
                            evaluationFailedEventDetails=EvaluationFailedEventDetails(
                                cause=f"Map state input must be an array but was: {type(input_items)}",
                                error=error_name.error_name,
                            )
                        ),
                    )
                    raise FailureEventException(failure_event=failure_event)
                env.event_manager.add_event(
                    context=env.event_history_context,
                    event_type=HistoryEventType.MapStateStarted,
                    event_details=EventDetails(
                        mapStateStartedEventDetails=MapStateStartedEventDetails(
                            length=len(input_items)
                        )
                    ),
                )

            self.tolerated_failure_count_decl.eval(env=frame)
            tolerated_failure_count = frame.stack.pop()
            self.tolerated_failure_percentage_decl.eval(env=frame)
            tolerated_failure_percentage = frame.stack.pop()
        finally:
            env.close_frame(frame)

        if isinstance(self.iteration_component, InlineIterator):
            eval_input = InlineIteratorEvalInput(
                state_name=self.name,
                max_concurrency=max_concurrency_num,
                input_items=input_items,
                parameters=self.parameters,
                item_selector=self.item_selector,
            )
        elif isinstance(self.iteration_component, InlineItemProcessor):
            eval_input = InlineItemProcessorEvalInput(
                state_name=self.name,
                max_concurrency=max_concurrency_num,
                input_items=input_items,
                item_selector=self.item_selector,
                parameters=self.parameters,
            )
        else:
            map_run_record = MapRunRecord(
                state_machine_arn=env.states.context_object.context_object_data["StateMachine"][
                    "Id"
                ],
                execution_arn=env.states.context_object.context_object_data["Execution"]["Id"],
                max_concurrency=max_concurrency_num,
                tolerated_failure_count=tolerated_failure_count,
                tolerated_failure_percentage=tolerated_failure_percentage,
                label=label,
            )
            env.map_run_record_pool_manager.add(map_run_record)
            # Choose the distributed input type depending on whether the definition
            # asks for the legacy Iterator component or an ItemProcessor
            if isinstance(self.iteration_component, DistributedIterator):
                distributed_eval_input_class = DistributedIteratorEvalInput
            elif isinstance(self.iteration_component, DistributedItemProcessor):
                distributed_eval_input_class = DistributedItemProcessorEvalInput
            else:
                raise RuntimeError(
                    f"Unknown iteration component of type '{type(self.iteration_component)}' '{self.iteration_component}'."
                )
            eval_input = distributed_eval_input_class(
                state_name=self.name,
                max_concurrency=max_concurrency_num,
                input_items=input_items,
                parameters=self.parameters,
                item_selector=self.item_selector,
                item_reader=self.item_reader,
                tolerated_failure_count=tolerated_failure_count,
                tolerated_failure_percentage=tolerated_failure_percentage,
                label=label,
                map_run_record=map_run_record,
            )

        env.stack.append(eval_input)
        self.iteration_component.eval(env)

        if self.result_writer:
            self.result_writer.eval(env)

        env.event_manager.add_event(
            context=env.event_history_context,
            event_type=HistoryEventType.MapStateSucceeded,
            update_source_event_id=False,
        )

    def _eval_state(self, env: Environment) -> None:
        # Initialise the retry counter for execution states.
        env.states.context_object.context_object_data["State"]["RetryCount"] = 0

        # Attempt to evaluate the state's logic through until it's successful, caught, or retries have run out.
        while env.is_running():
            try:
                self._evaluate_with_timeout(env)
                break
            except Exception as ex:
                failure_event: FailureEvent = self._from_error(env=env, ex=ex)
                error_output = self._construct_error_output_value(failure_event=failure_event)
                env.states.set_error_output(error_output)
                env.states.set_result(error_output)

                if self.retry:
                    retry_outcome: RetryOutcome = self._handle_retry(
                        env=env, failure_event=failure_event
                    )
                    if retry_outcome == RetryOutcome.CanRetry:
                        continue

                if failure_event.event_type != HistoryEventType.ExecutionFailed:
                    if (
                        isinstance(ex, FailureEventException)
                        and failure_event.event_type == HistoryEventType.EvaluationFailed
                    ):
                        env.event_manager.add_event(
                            context=env.event_history_context,
                            event_type=HistoryEventType.EvaluationFailed,
                            event_details=EventDetails(
                                evaluationFailedEventDetails=ex.get_evaluation_failed_event_details(),
                            ),
                        )
                    env.event_manager.add_event(
                        context=env.event_history_context,
                        event_type=HistoryEventType.MapStateFailed,
                    )

                if self.catch:
                    self._handle_catch(env=env, failure_event=failure_event)
                    catch_outcome: CatchOutcome = env.stack[-1]
                    if catch_outcome == CatchOutcome.Caught:
                        break

                self._handle_uncaught(env=env, failure_event=failure_event)
