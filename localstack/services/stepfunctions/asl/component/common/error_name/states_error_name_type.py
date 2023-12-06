from __future__ import annotations

from enum import Enum
from typing import Final

from localstack.services.stepfunctions.asl.antlr.runtime.ASLLexer import ASLLexer


class StatesErrorNameType(Enum):
    StatesALL = ASLLexer.ERRORNAMEStatesALL
    StatesHeartbeatTimeout = ASLLexer.ERRORNAMEStatesHeartbeatTimeout
    StatesTimeout = ASLLexer.ERRORNAMEStatesTimeout
    StatesTaskFailed = ASLLexer.ERRORNAMEStatesTaskFailed
    StatesPermissions = ASLLexer.ERRORNAMEStatesPermissions
    StatesResultPathMatchFailure = ASLLexer.ERRORNAMEStatesResultPathMatchFailure
    StatesParameterPathFailure = ASLLexer.ERRORNAMEStatesParameterPathFailure
    StatesBranchFailed = ASLLexer.ERRORNAMEStatesBranchFailed
    StatesNoChoiceMatched = ASLLexer.ERRORNAMEStatesNoChoiceMatched
    StatesIntrinsicFailure = ASLLexer.ERRORNAMEStatesIntrinsicFailure
    StatesExceedToleratedFailureThreshold = ASLLexer.ERRORNAMEStatesExceedToleratedFailureThreshold
    StatesItemReaderFailed = ASLLexer.ERRORNAMEStatesItemReaderFailed
    StatesResultWriterFailed = ASLLexer.ERRORNAMEStatesResultWriterFailed
    StatesRuntime = ASLLexer.ERRORNAMEStatesRuntime

    def to_name(self) -> str:
        return _error_name(self)

    @classmethod
    def from_name(cls, name: str) -> StatesErrorNameType:
        error_name = _REVERSE_NAME_LOOKUP.get(name, None)
        if error_name is None:
            raise ValueError(f"Unknown ErrorName type, got: '{name}'.")
        return cls(error_name.value)


def _error_name(error_name: StatesErrorNameType) -> str:
    return ASLLexer.literalNames[error_name.value][2:-2]


def _reverse_error_name_lookup() -> dict[str, StatesErrorNameType]:
    lookup: dict[str, StatesErrorNameType] = dict()
    for error_name in StatesErrorNameType:
        error_text: str = _error_name(error_name)
        lookup[error_text] = error_name
    return lookup


_REVERSE_NAME_LOOKUP: Final[dict[str, StatesErrorNameType]] = _reverse_error_name_lookup()
