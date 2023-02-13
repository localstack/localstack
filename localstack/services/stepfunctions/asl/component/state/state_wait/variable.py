from typing import Final

from jsonpath_ng import parse

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_stmt import (
    ComparisonStmt,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class NoSuchVariable:
    def __init__(self, path: str):
        self.path: Final[str] = path


class Variable(ComparisonStmt):
    def __init__(self, value: str):
        self.value: Final[str] = value

    def _eval_body(self, env: Environment) -> None:
        variable_expr = parse(self.value)
        try:
            value = variable_expr.find(env.inp)
        except Exception as ex:
            value = NoSuchVariable(f"{self.value}, {ex}")
        env.stack.append(value)
