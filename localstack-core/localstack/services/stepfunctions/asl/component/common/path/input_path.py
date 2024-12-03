import abc
import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class InputPath(EvalComponent, abc.ABC): ...


class InputPathBase(InputPath):
    DEFAULT_PATH: Final[str] = "$"

    path: Final[Optional[str]]

    def __init__(self, path: Optional[str]):
        self.path = path

    def _eval_body(self, env: Environment) -> None:
        match self.path:
            case None:
                value = dict()
            case self.DEFAULT_PATH:
                value = env.states.get_input()
            case _:
                value = extract_json(self.path, env.states.get_input())
        env.stack.append(copy.deepcopy(value))


class InputPathContextObject(InputPathBase):
    def __init__(self, path: str):
        path_tail = path[1:]
        super().__init__(path=path_tail)

    def _eval_body(self, env: Environment) -> None:
        value = extract_json(self.path, env.states.context_object.context_object_data)
        env.stack.append(copy.deepcopy(value))


class InputPathVar(InputPath):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        self.variable_sample = variable_sample

    def _eval_body(self, env: Environment) -> None:
        self.variable_sample.eval(env=env)
