import copy
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class ToleratedFailureCount(EvalComponent):
    DEFAULT: Final[int] = 0  # No threshold.

    def __init__(self, count: int = DEFAULT):
        self.count: Final[int] = count

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.count)


class ToleratedFailureCountPath(EvalComponent):
    def __init__(self, path: str):
        self.path: Final[str] = path

    def _eval_body(self, env: Environment) -> None:
        value = JSONPathUtils.extract_json(self.path, env.stack[-1])
        env.stack.append(copy.deepcopy(value))


class ToleratedFailurePercentage(EvalComponent):
    DEFAULT: Final[float] = 0.0

    def __init__(self, percentage: float = DEFAULT):
        self.percentage: Final[float] = percentage

    def _eval_body(self, env: Environment) -> None:
        env.stack.append(self.percentage)


class ToleratedFailurePercentagePath(EvalComponent):
    def __init__(self, path: str):
        self.path: Final[str] = path

    def _eval_body(self, env: Environment) -> None:
        value = JSONPathUtils.extract_json(self.path, env.stack[-1])
        env.stack.append(copy.deepcopy(value))
