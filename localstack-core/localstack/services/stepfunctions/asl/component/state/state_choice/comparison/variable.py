from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class NoSuchVariable:
    def __init__(self, path: str):
        self.path: Final[str] = path


class Variable(EvalComponent):
    def __init__(self, value: str):
        self.value: Final[str] = value

    def _eval_body(self, env: Environment) -> None:
        try:
            inp = env.stack[-1]
            value = extract_json(self.value, inp)
        except Exception as ex:
            value = NoSuchVariable(f"{self.value}, {ex}")
        env.stack.append(value)


class VariableContextObject(Variable):
    def __init__(self, value: str):
        value_tail = value[1:]
        super().__init__(value=value_tail)

    def _eval_body(self, env: Environment) -> None:
        try:
            value = extract_json(self.value, env.context_object_manager.context_object)
        except Exception as ex:
            value = NoSuchVariable(f"{self.value}, {ex}")
        env.stack.append(value)
