from __future__ import annotations

import abc
from typing import Any, Final

from localstack.services.stepfunctions.asl.component.common.assign.assign_template_value import (
    AssignTemplateValue,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.intrinsic.function.function import Function
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.parse.intrinsic.intrinsic_parser import IntrinsicParser
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


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


class AssignTemplateBindingPath(AssignTemplateBinding):
    path: Final[str]

    def __init__(self, identifier: str, path: str):
        super().__init__(identifier=identifier)
        self.path = path

    def _eval_value(self, env: Environment) -> Any:
        memory_value = env.stack[-1]
        path_output = extract_json(self.path, memory_value)
        return path_output


class AssignTemplateBindingPathContext(AssignTemplateBindingPath):
    @classmethod
    def from_raw(
        cls, identifier: str, string_path_context_obj: str
    ) -> AssignTemplateBindingPathContext:
        path_context_obj: str = string_path_context_obj[1:]
        return cls(identifier=identifier, path=path_context_obj)

    def _eval_value(self, env: Environment) -> Any:
        path_output = extract_json(self.path, env.states.context_object.context_object_data)
        return path_output


class AssignTemplateBindingIntrinsicFunction(AssignTemplateBinding):
    function_literal: Final[str]
    function: Final[Function]

    def __init__(self, identifier: str, function_literal: str):
        super().__init__(identifier=identifier)
        self.function_literal = function_literal
        self.function, _ = IntrinsicParser.parse(self.function_literal)

    def _eval_value(self, env: Environment) -> Any:
        # TODO: resolve jsonata variable references as arguments.
        #  should probably be done in the function object.
        self.function.eval(env=env)
        val = env.stack.pop()
        return val


class AssignTemplateBindingVar(AssignTemplateBinding):
    variable_sample: Final[VariableSample]

    def __init__(self, identifier: str, variable_sample: VariableSample):
        super().__init__(identifier=identifier)
        self.variable_sample = variable_sample

    def _eval_value(self, env: Environment) -> Any:
        self.variable_sample.eval(env=env)
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
