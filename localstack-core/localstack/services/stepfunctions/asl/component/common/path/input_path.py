import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class InputPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"

    path: Final[Optional[str]]

    def __init__(self, path: Optional[str]):
        self.path = path

    def _eval_body(self, env: Environment) -> None:
        match self.path:
            case None:
                value = dict()
            case InputPath.DEFAULT_PATH:
                value = env.inp
            case _:
                value = extract_json(self.path, env.inp)
        env.stack.append(copy.deepcopy(value))


class InputPathContextObject(InputPath):
    def __init__(self, path: str):
        path_tail = path[1:]
        super().__init__(path=path_tail)

    def _eval_body(self, env: Environment) -> None:
        value = extract_json(self.path, env.context_object_manager.context_object)
        env.stack.append(copy.deepcopy(value))
