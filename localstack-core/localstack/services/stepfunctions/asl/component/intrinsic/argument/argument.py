import abc
from typing import Any, Final, Optional

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringVariableSample,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class Argument(EvalComponent, abc.ABC):
    """
    Represents an Intrinsic Function argument that can be evaluated and whose
    result is pushed onto the stack.

    Subclasses must override `_eval_argument()` to evaluate the specific value
    of the argument they represent. This abstract class manages the type and
    environment handling by appending the evaluated result to the environment's
    stack in `_eval_body`.

    The `_eval_body` method calls `_eval_argument()` and pushes the resulting
    value to the stack.
    """

    @abc.abstractmethod
    def _eval_argument(self, env: Environment) -> Any: ...

    def _eval_body(self, env: Environment) -> None:
        argument = self._eval_argument(env=env)
        env.stack.append(argument)


class ArgumentLiteral(Argument):
    definition_value: Final[Optional[Any]]

    def __init__(self, definition_value: Optional[Any]):
        self.definition_value = definition_value

    def _eval_argument(self, env: Environment) -> Any:
        return self.definition_value


class ArgumentJsonPath(Argument):
    json_path: Final[str]

    def __init__(self, json_path: str):
        self.json_path = json_path

    def _eval_argument(self, env: Environment) -> Any:
        inp = env.stack[-1]
        value = extract_json(self.json_path, inp)
        return value


class ArgumentContextPath(ArgumentJsonPath):
    def __init__(self, context_path: str):
        json_path = context_path[1:]
        super().__init__(json_path=json_path)

    def _eval_argument(self, env: Environment) -> Any:
        value = extract_json(self.json_path, env.states.context_object.context_object_data)
        return value


class ArgumentFunction(Argument):
    function: Final[EvalComponent]

    def __init__(self, function: EvalComponent):
        self.function = function

    def _eval_argument(self, env: Environment) -> Any:
        self.function.eval(env=env)
        output_value = env.stack.pop()
        return output_value


class ArgumentVar(Argument):
    string_variable_sample: Final[StringVariableSample]

    def __init__(self, string_variable_sample: StringVariableSample):
        super().__init__()
        self.string_variable_sample = string_variable_sample

    def _eval_argument(self, env: Environment) -> Any:
        self.string_variable_sample.eval(env=env)
        value = env.stack.pop()
        return value


class ArgumentList(Argument):
    arguments: Final[list[Argument]]
    size: Final[int]

    def __init__(self, arguments: list[Argument]):
        self.arguments = arguments
        self.size = len(arguments)

    def _eval_argument(self, env: Environment) -> Any:
        values = list()
        for argument in self.arguments:
            argument.eval(env=env)
            argument_value = env.stack.pop()
            values.append(argument_value)
        return values
