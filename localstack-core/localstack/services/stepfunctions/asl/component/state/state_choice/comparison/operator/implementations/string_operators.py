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
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = variable == comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringEquals._compare(variable, value)
        env.stack.append(res)


class StringEqualsPath(StringEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = StringEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class StringGreaterThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = variable > comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringGreaterThan._compare(variable, value)
        env.stack.append(res)


class StringGreaterThanPath(StringGreaterThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = StringGreaterThanPath._compare(variable, comp_value)
        env.stack.append(res)


class StringGreaterThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = variable >= comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringGreaterThanEquals._compare(variable, value)
        env.stack.append(res)


class StringGreaterThanEqualsPath(StringGreaterThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringGreaterThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = StringGreaterThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class StringLessThan(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThan)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = variable < comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringLessThan._compare(variable, value)
        env.stack.append(res)


class StringLessThanPath(StringLessThan):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = StringLessThanPath._compare(variable, comp_value)
        env.stack.append(res)


class StringLessThanEquals(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanEquals)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = variable <= comparison_value
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringLessThanEquals._compare(variable, value)
        env.stack.append(res)


class StringLessThanEqualsPath(StringLessThanEquals):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringLessThanEqualsPath)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        inp = env.stack[-1]
        comp_value = JSONPathUtils.extract_json(value, inp)
        res = StringLessThanEqualsPath._compare(variable, comp_value)
        env.stack.append(res)


class StringMatches(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.StringMatches)

    @staticmethod
    def _compare(variable: Any, comparison_value: Any) -> bool:
        res = False
        if isinstance(variable, str):
            res = fnmatch.fnmatch(variable, comparison_value)
        return res

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = StringMatches._compare(variable, value)
        env.stack.append(res)
