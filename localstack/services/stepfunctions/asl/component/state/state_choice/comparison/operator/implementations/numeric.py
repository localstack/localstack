from typing import Any

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


def _is_numeric(variable: Any) -> bool:
    return isinstance(variable, (int, float)) and not isinstance(variable, bool)


class NumericEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if _is_numeric(variable):
            res = variable == value
        env.stack.append(res)


class NumericEqualsPath(NumericEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        NumericEquals.eval(env=env, value=comp_value)


class NumericGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if _is_numeric(variable):
            res = variable > value
        env.stack.append(res)


class NumericGreaterThanPath(NumericGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        NumericGreaterThan.eval(env=env, value=comp_value)


class NumericGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if _is_numeric(variable):
            res = variable >= value
        env.stack.append(res)


class NumericGreaterThanEqualsPath(NumericGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        NumericGreaterThanEquals.eval(env=env, value=comp_value)


class NumericLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if _is_numeric(variable):
            res = variable < value
        env.stack.append(res)


class NumericLessThanPath(NumericLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        NumericLessThan.eval(env=env, value=comp_value)


class NumericLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if _is_numeric(variable):
            res = variable <= value
        env.stack.append(res)


class NumericLessThanEqualsPath(NumericLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        NumericLessThanEquals.eval(env=env, value=comp_value)
