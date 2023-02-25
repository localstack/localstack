from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class OutputPath(EvalComponent):
    DEFAULT_PATH: Final[str] = "$"

    def __init__(self, output_path: str):
        self.output_path: Final[str] = output_path

    def _eval_body(self, env: Environment) -> None:
        if self.output_path != OutputPath.DEFAULT_PATH:
            value = JSONPathUtils.extract_json(self.output_path, env.inp)
            env.inp = value
