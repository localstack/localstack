import fnmatch
from typing import Any

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class StringEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = variable == value
        env.stack.append(res)


class StringEqualsPath(StringEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        StringEquals.eval(env=env, value=comp_value)


class StringGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = variable > value
        env.stack.append(res)


class StringGreaterThanPath(StringGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        StringGreaterThan.eval(env=env, value=comp_value)


class StringGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = variable >= value
        env.stack.append(res)


class StringGreaterThanEqualsPath(StringGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        StringGreaterThanEquals.eval(env=env, value=comp_value)


class StringLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThan)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = variable < value
        env.stack.append(res)


class StringLessThanPath(StringLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        StringLessThan.eval(env=env, value=comp_value)


class StringLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanEquals)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = variable <= value
        env.stack.append(res)


class StringLessThanEqualsPath(StringLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        comp_value = JSONPathUtils.extract_json(value, env.inp)
        StringLessThanEquals.eval(env=env, value=comp_value)


class StringMatches(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringMatches)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = False
        if isinstance(variable, str):
            res = fnmatch.fnmatch(variable, value)
        env.stack.append(res)
