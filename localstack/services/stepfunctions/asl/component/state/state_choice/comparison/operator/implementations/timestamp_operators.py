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
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class TimestampEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(value)
                res = a == b
        env.stack.append(res)


class TimestampEqualsPath(TimestampEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        TimestampEquals.eval(env=env, value=comp_value)


class TimestampGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(value)
                res = a > b
        env.stack.append(res)


class TimestampGreaterThanPath(TimestampGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        TimestampGreaterThan.eval(env=env, value=comp_value)


class TimestampGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(value)
                res = a >= b
        env.stack.append(res)


class TimestampGreaterThanEqualsPath(TimestampGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        TimestampGreaterThanEquals.eval(env=env, value=comp_value)


class TimestampLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(value)
                res = a < b
        env.stack.append(res)


class TimestampLessThanPath(TimestampLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        TimestampLessThan.eval(env=env, value=comp_value)


class TimestampLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            a = IsTimestamp.string_to_timestamp(variable)
            if a is not None:
                b = IsTimestamp.string_to_timestamp(value)
                res = a <= b
        env.stack.append(res)


class TimestampLessThanEqualsPath(TimestampLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.TimestampLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        TimestampLessThanEquals.eval(env=env, value=comp_value)
