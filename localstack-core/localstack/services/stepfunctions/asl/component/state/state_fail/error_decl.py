import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_terminal import (
    JSONataTemplateValueTerminalExpression,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_fuinction_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class ErrorDecl(EvalComponent, abc.ABC): ...


class ErrorConst(ErrorDecl):
    value: Final[str]

    def __init__(self, value: str):
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.value)


class ErrorVar(ErrorDecl):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)


class ErrorJSONata(ErrorDecl):
    jsonata_template_value_terminal_expression: Final[JSONataTemplateValueTerminalExpression]

    def __init__(
        self, jsonata_template_value_terminal_expression: JSONataTemplateValueTerminalExpression
    ):
        super().__init__()
        self.jsonata_template_value_terminal_expression = jsonata_template_value_terminal_expression

    def _eval_body(self, env: Environment) -> None:
        self.jsonata_template_value_terminal_expression.eval(env=env)


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


class ErrorPathJsonPath(ErrorConst):
    def _eval_body(self, env: Environment) -> None:
        current_output = env.stack[-1]
        cause = extract_json(self.value, current_output)
        env.stack.append(cause)


class ErrorPathIntrinsicFunction(ErrorConst):
    function: Final[Function]

    def __init__(self, value: str) -> None:
        super().__init__(value=value)
        self.function, _ = IntrinsicParser.parse(value)
        if self.function.name.name not in _STRING_RETURN_FUNCTIONS:
            raise ValueError(
                f"Unsupported Intrinsic Function for ErrorPath declaration: '{self.value}'."
            )

    def _eval_body(self, env: Environment) -> None:
        self.function.eval(env=env)
