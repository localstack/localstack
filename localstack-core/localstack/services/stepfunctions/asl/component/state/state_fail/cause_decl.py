import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringExpression,
    StringIntrinsicFunction,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment

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


class CauseDecl(EvalComponent, abc.ABC): ...


class Cause(CauseDecl):
    string_expression: Final[StringExpression]

    def __init__(self, string_expression: StringExpression):
        self.string_expression = string_expression

    def _eval_body(self, env: Environment) -> None:
        self.string_expression.eval(env=env)


class CausePath(Cause):
    def __init__(self, string_expression: StringExpression):
        super().__init__(string_expression=string_expression)
        if isinstance(string_expression, StringIntrinsicFunction):
            if string_expression.function.name.name not in _STRING_RETURN_FUNCTIONS:
                raise ValueError(
                    f"Unsupported Intrinsic Function for CausePath declaration: '{string_expression.intrinsic_function_derivation}'."
                )
