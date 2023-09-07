from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class NoSuchVariable:
    def __init__(self, path: str):
        self.path: Final[str] = path


class Variable(EvalComponent):
    def __init__(self, value: str):
        self.value: Final[str] = value

    def _eval_body(self, env: Environment) -> None:
        try:
            value = JSONPathUtils.extract_json(self.value, env.inp)
        except Exception as ex:
            value = NoSuchVariable(f"{self.value}, {ex}")
        env.stack.append(value)
