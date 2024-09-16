from typing import Any

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class BooleanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.BooleanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, bool):
            res = variable is value
        env.stack.append(res)


class BooleanEqualsPath(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.BooleanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()

        inp = env.stack[-1]
        comp_value: bool = extract_json(value, inp)
        if not isinstance(comp_value, bool):
            raise TypeError(f"Expected type bool, but got '{comp_value}' from path '{value}'.")

        res = False
        if isinstance(variable, bool):
            res = bool(variable) is comp_value
        env.stack.append(res)
