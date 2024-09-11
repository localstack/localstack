import copy
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class ItemsPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"
    path: Final[str]

    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path

    def _eval_body(self, env: Environment) -> None:
        value = copy.deepcopy(env.stack[-1])
        if self.path != ItemsPath.DEFAULT_PATH:
            value = extract_json(self.path, value)
        env.stack.append(value)


class ItemsPathContextObject(ItemsPath):
    def __init__(self, path: str):
        path_tail = path[1:]
        super().__init__(path=path_tail)

    def _eval_body(self, env: Environment) -> None:
        value = extract_json(self.path, env.context_object_manager.context_object)
        env.stack.append(copy.deepcopy(value))
