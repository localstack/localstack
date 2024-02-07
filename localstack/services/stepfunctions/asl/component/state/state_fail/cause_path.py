from typing import Final

from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.cause_decl import CauseDecl
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils

_STRING_RETURN_FUNCTIONS: Final[set[str]] = {
    typ.name()
    for typ in [
        StatesFunctionNameType.Format,
        StatesFunctionNameType.JsonToString,
        StatesFunctionNameType.ArrayGetItem,
        StatesFunctionNameType.Base64Decode,
        StatesFunctionNameType.Base64Encode,
        StatesFunctionNameType.Hash,
        StatesFunctionNameType.UUID,
    ]
}


class CausePath(CauseDecl):
    ...


class CausePathJsonPath(CausePath):
    def _eval_body(self, env: Environment) -> None:
        current_output = env.stack[-1]
        cause = JSONPathUtils.extract_json(self.value, current_output)
        env.stack.append(cause)


class CausePathIntrinsicFunction(CausePath):
    function: Final[Function]

    def __init__(self, value: str) -> None:
        super().__init__(value=value)
        self.function = IntrinsicParser.parse(value)
        if self.function.name.name not in _STRING_RETURN_FUNCTIONS:
            raise ValueError(
                f"Unsupported Intrinsic Function for CausePath declaration: '{self.value}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.function.eval(env=env)
