from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


class CauseDecl(EvalComponent):
    value: Final[str]

    def __init__(self, value: str):
        self.value = value

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.value)
