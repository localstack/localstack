from __future__ import annotations

from typing import Final

from localstack.services.stepfunctions.asl.component.common.error_name.error_name import ErrorName
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)


class StatesErrorName(ErrorName):
    def __init__(self, typ: StatesErrorNameType):
        super().__init__(error_name=typ.to_name())
        self.typ: Final[StatesErrorNameType] = typ

    @classmethod
    def from_name(cls, error_name: str) -> StatesErrorName:
        error_name_type: StatesErrorNameType = StatesErrorNameType.from_name(error_name)
        return cls(typ=error_name_type)
