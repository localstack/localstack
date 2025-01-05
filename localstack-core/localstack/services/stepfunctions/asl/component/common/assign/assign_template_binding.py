from __future__ import annotations

import abc
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value import (
    AssignTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringExpressionSimple,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class AssignTemplateBinding(EvalComponent, abc.ABC):
    identifier: Final[str]

    def __init__(self, identifier: str):
        super().__init__()
        self.identifier = identifier

    @abc.abstractmethod
    def _eval_value(self, env: Environment) -> Any: ...

    def _eval_body(self, env: Environment) -> None:
        assign_object: dict = env.stack.pop()
        assign_value = self._eval_value(env=env)
        assign_object[self.identifier] = assign_value
        env.stack.append(assign_object)


class AssignTemplateBindingStringExpressionSimple(AssignTemplateBinding):
    string_expression_simple: Final[StringExpressionSimple]

    def __init__(self, identifier: str, string_expression_simple: StringExpressionSimple):
        super().__init__(identifier=identifier)
        self.string_expression_simple = string_expression_simple

    def _eval_value(self, env: Environment) -> Any:
        self.string_expression_simple.eval(env=env)
        value = env.stack.pop()
        return value


class AssignTemplateBindingValue(AssignTemplateBinding):
    assign_value: Final[AssignTemplateValue]

    def __init__(self, identifier: str, assign_value: AssignTemplateValue):
        super().__init__(identifier=identifier)
        self.assign_value = assign_value

    def _eval_value(self, env: Environment) -> Any:
        self.assign_value.eval(env=env)
        value = env.stack.pop()
        return value
