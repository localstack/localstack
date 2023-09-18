import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    ReaderConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import StateTask
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ItemReader(EvalComponent):
    _state_task: Final[StateTask]
    _parameters: Final[Optional[Parameters]]
    _reader_config: Final[Optional[ReaderConfig]]

    def __init__(
        self,
        state_task: StateTask,
        parameters: Optional[Parameters],
        reader_config: Optional[ReaderConfig],
    ):
        self._state_task = state_task
        self._parameters = parameters
        self._reader_config = reader_config

    @property
    def _resource(self):
        return self._state_task.resource

    def __str__(self):
        class_dict = copy.deepcopy(self.__dict__)
        del class_dict["_state_task"]
        class_dict["resource"] = self._resource
        return f"({self.__class__.__name__}| {class_dict})"

    def _eval_body(self, env: Environment) -> None:
        pass
