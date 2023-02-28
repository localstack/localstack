from typing import Any

from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.variable import NoSuchVariable
from localstack.services.stepfunctions.asl.eval.environment import Environment


class IsBoolean(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsBoolean)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = value if isinstance(variable, bool) else not value
        env.stack.append(res)


class IsNull(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsNull)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        is_null = variable is None and not isinstance(variable, NoSuchVariable)
        res = is_null is value
        env.stack.append(res)


class IsNumeric(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsNumeric)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = (
            value
            if isinstance(variable, (int, float)) and not isinstance(variable, bool)
            else not value
        )
        env.stack.append(res)


class IsPresent(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsPresent)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = value if not isinstance(variable, NoSuchVariable) else not value
        env.stack.append(res)


class IsString(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsString)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = value if isinstance(variable, str) else not value
        env.stack.append(res)


class IsTimestamp(Operator):
    @staticmethod
    def impl_name() -> str:
        return str(ComparisonOperatorType.IsString)

    @staticmethod
    def eval(env: Environment, value: Any) -> None:
        variable = env.stack.pop()
        res = value if isinstance(variable, str) else not value
        env.stack.append(res)
