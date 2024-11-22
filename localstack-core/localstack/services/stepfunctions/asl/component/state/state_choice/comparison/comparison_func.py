from __future__ import annotations

import abc
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_operator_type import (
    ComparisonOperatorType,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.comparison_type import (
    Comparison,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.factory import (
    OperatorFactory,
)
from localstack.services.stepfunctions.asl.component.state.state_choice.comparison.operator.operator import (
    Operator,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ComparisonFunc(Comparison, abc.ABC):
    operator_type: Final[ComparisonOperatorType]

    def __init__(self, operator_type: ComparisonOperatorType):
        self.operator_type = operator_type


class ComparisonFuncValue(ComparisonFunc):
    value: Final[Any]

    def __init__(self, operator_type: ComparisonOperatorType, value: Any):
        super().__init__(operator_type=operator_type)
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        operator: Operator = OperatorFactory.get(self.operator_type)
        operator.eval(env=env, value=self.value)


class ComparisonFuncVar(ComparisonFuncValue):
    _COMPARISON_FUNC_VAR_VALUE: Final[str] = "$"
    variable_sample: Final[VariableSample]

    def __init__(self, operator_type: ComparisonOperatorType, variable_sample: VariableSample):
        super().__init__(operator_type=operator_type, value=self._COMPARISON_FUNC_VAR_VALUE)
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)
        super()._eval_body(env=env)
        # Purge the outcome of the variable sampling form the
        # stack as operators do not digest the input value.
        del env.stack[-2]
