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
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if _is_numeric(variable):
            res = variable == comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = NumericEquals._compare(variable, value)
        env.stack.append(res)


class NumericEqualsPath(NumericEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = NumericEquals._compare(variable, comp_value)
        env.stack.append(res)


class NumericGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if _is_numeric(variable):
            res = variable > comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = NumericGreaterThan._compare(variable, value)
        env.stack.append(res)


class NumericGreaterThanPath(NumericGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = NumericGreaterThanPath._compare(variable, comp_value)
        env.stack.append(res)


class NumericGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if _is_numeric(variable):
            res = variable >= comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = NumericGreaterThanEquals._compare(variable, value)
        env.stack.append(res)


class NumericGreaterThanEqualsPath(NumericGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = NumericGreaterThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class NumericLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if _is_numeric(variable):
            res = variable < comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = NumericLessThan._compare(variable, value)
        env.stack.append(res)


class NumericLessThanPath(NumericLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = NumericLessThanPath._compare(variable, comp_value)
        env.stack.append(res)


class NumericLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if _is_numeric(variable):
            res = variable <= comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = NumericLessThanEquals._compare(variable, value)
        env.stack.append(res)


class NumericLessThanEqualsPath(NumericLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.NumericLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = NumericLessThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)
