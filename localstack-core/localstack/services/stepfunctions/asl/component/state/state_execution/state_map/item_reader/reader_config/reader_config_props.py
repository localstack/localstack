from typing import Any, Final

from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.max_items_decl import (
    MaxItemsDecl,
)
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class ReaderConfigProps(TypedProps):
    _UNIQUE_SUB_INSTANCES: Final[set[type]] = {MaxItemsDecl}
    name: str

    def add(self, instance: Any) -> None:
        inst_type = type(instance)

        # Subclasses
        for typ in self._UNIQUE_SUB_INSTANCES:
            if issubclass(inst_type, typ):
                super()._add(typ, instance)
                return

        # Base and delegate to preprocessor.
        super().add(instance)
