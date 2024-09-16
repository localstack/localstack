from typing import Any

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.implementations.is_operator import (
    IsTimestamp,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class TimestampEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(comparison_value)
                res = a == b
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = TimestampEquals._compare(variable, value)
        env.stack.append(res)


class TimestampEqualsPath(TimestampEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = extract_json(value, inp)
        res = TimestampEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class TimestampGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(comparison_value)
                res = a > b
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = TimestampGreaterThan._compare(variable, value)
        env.stack.append(res)


class TimestampGreaterThanPath(TimestampGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = extract_json(value, inp)
        res = TimestampGreaterThanPath._compare(variable, comp_value)
        env.stack.append(res)


class TimestampGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(comparison_value)
                res = a >= b
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = TimestampGreaterThanEquals._compare(variable, value)
        env.stack.append(res)


class TimestampGreaterThanEqualsPath(TimestampGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = extract_json(value, inp)
        res = TimestampGreaterThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class TimestampLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(comparison_value)
                res = a < b
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = TimestampLessThan._compare(variable, value)
        env.stack.append(res)


class TimestampLessThanPath(TimestampLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = extract_json(value, inp)
        res = TimestampLessThanPath._compare(variable, comp_value)
        env.stack.append(res)


class TimestampLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(comparison_value)
                res = a <= b
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = TimestampLessThanEquals._compare(variable, value)
        env.stack.append(res)


class TimestampLessThanEqualsPath(TimestampLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = extract_json(value, inp)
        res = TimestampLessThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)
