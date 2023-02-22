from typing import Optional

from localstack.aws.api.stepfunctions import HistoryEventType
from localstack.services.stepfunctions.asl.component.common.catch.catch_decl import CatchDecl
from localstack.services.stepfunctions.asl.component.common.path.items_path import ItemsPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.common.retry.retry_decl import RetryDecl
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
from localstack.services.stepfunctions.asl.eval.contextobject.contex_object import Item, Map
from localstack.services.stepfunctions.asl.eval.environment import Environment


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

    def _eval_body(self, env: Environment) -> None:
        env.context_object["Map"] = Map(Item=Item(Index=-1, Value="Unsupported"))
        super(StateMap, self)._eval_body(env=env)
        env.context_object["Map"] = None

    def _eval_execution(self, env: Environment) -> None:
        # Reduce the input to the list of items.
        self.items_path.eval(env)

        # Launch the item processor.
        self.item_processor.eval(env)
