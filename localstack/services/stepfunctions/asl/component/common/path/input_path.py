import copy
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class InputPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"

    input_path_src: Final[Optional[str]]

    def __init__(self, input_path_src: Optional[str]):
        self.input_path_src = input_path_src

    def _eval_body(self, env: Environment) -> None:
        match self.input_path_src:
            case None:
                value = dict()
            case InputPath.DEFAULT_PATH:
                value = env.inp
            case _:
                value = JSONPathUtils.extract_json(self.input_path_src, env.inp)
        env.stack.append(copy.deepcopy(value))
