from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.parargs import Parargs
from localstack.services.stepfunctions.asl.component.common.path.input_path import InputPath
from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.component.state.state_props import StateProps

EQUAL_SUBTYPES: Final[list[type]] = [InputPath, Parargs, ResultSelector, ResultPath, Result]


class TestStateStateProps(StateProps):
    def add(self, instance: Any) -> None:
        inst_type = type(instance)
        # Subclasses
        for typ in EQUAL_SUBTYPES:
            if issubclass(inst_type, typ):
                self._add(typ, instance)
                return
        super().add(instance=instance)
