from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class ItemsPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"

    def __init__(self, items_path_src: str = DEFAULT_PATH):
        self.items_path_src: Final[str] = items_path_src

    def _eval_body(self, env: Environment) -> None:
        if self.items_path_src != ItemsPath.DEFAULT_PATH:
            value = env.stack.pop()
            value = JSONPathUtils.extract_json(self.items_path_src, value)
            env.stack.append(value)
