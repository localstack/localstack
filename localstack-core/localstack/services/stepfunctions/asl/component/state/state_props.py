from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.common.parargs import Parargs
from localstack.services.stepfunctions.asl.component.common.timeouts.heartbeat import Heartbeat
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import Timeout
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_type import (
    Comparison,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.variable import (
    Variable,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.max_items_decl import (
    MaxItemsDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.items.items import (
    Items,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.max_concurrency import (
    MaxConcurrencyDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.tolerated_failure import (
    ToleratedFailureCountDecl,
    ToleratedFailurePercentageDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.cause_decl import CauseDecl
from localstack.services.stepfunctions.asl.component.state.state_fail.error_decl import ErrorDecl
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps

UNIQUE_SUBINSTANCES: Final[set[type]] = {
    Items,
    Resource,
    WaitFunction,
    Timeout,
    Heartbeat,
    MaxItemsDecl,
    MaxConcurrencyDecl,
    ToleratedFailureCountDecl,
    ToleratedFailurePercentageDecl,
    ErrorDecl,
    CauseDecl,
    Variable,
    Parargs,
    Comparison,
}


class StateProps(TypedProps):
    name: str

    def add(self, instance: Any) -> None:
        inst_type = type(instance)

        # End-Next conflicts:
        if inst_type == End and Next in self._instance_by_type:
            raise ValueError(f"End redefines Next, from '{self.get(Next)}' to '{instance}'.")
        if inst_type == Next and End in self._instance_by_type:
            raise ValueError(f"Next redefines End, from '{self.get(End)}' to '{instance}'.")

        # Subclasses
        for typ in UNIQUE_SUBINSTANCES:
            if issubclass(inst_type, typ):
                super()._add(typ, instance)
                return

        # Base and delegate to preprocessor.
        super().add(instance)
