import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.jsonata.jsonata_template_value_terminal import (
    JSONataTemplateValueTerminalExpression,
)
from localstack.services.stepfunctions.asl.component.common.variable_sample import VariableSample
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class Heartbeat(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _eval_seconds(self, env: Environment) -> int: ...

    def _eval_body(self, env: Environment) -> None:
        seconds = self._eval_seconds(env=env)
        env.stack.append(seconds)


class HeartbeatSeconds(Heartbeat):
    def __init__(self, heartbeat_seconds: int):
        if not isinstance(heartbeat_seconds, int) and heartbeat_seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for HeartbeatSeconds, got '{heartbeat_seconds}' instead."
            )
        self.heartbeat_seconds: Final[int] = heartbeat_seconds

    def _eval_seconds(self, env: Environment) -> int:
        return self.heartbeat_seconds


class HeartbeatSecondsJSONata(Heartbeat):
    jsonata_template_value_terminal_expression: Final[JSONataTemplateValueTerminalExpression]

    def __init__(
        self, jsonata_template_value_terminal_expression: JSONataTemplateValueTerminalExpression
    ):
        super().__init__()
        self.jsonata_template_value_terminal_expression = jsonata_template_value_terminal_expression

    def _eval_seconds(self, env: Environment) -> int:
        self.jsonata_template_value_terminal_expression.eval(env=env)
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        seconds = int(env.stack.pop())
        return seconds


class HeartbeatSecondsPath(Heartbeat):
    def __init__(self, path: str):
        self.path: Final[str] = path

    @classmethod
    def from_raw(cls, path: str):
        return cls(path=path)

    def _eval_seconds(self, env: Environment) -> int:
        inp = env.stack[-1]
        seconds = extract_json(self.path, inp)
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for HeartbeatSecondsPath, got '{seconds}' instead."
            )
        return seconds


class HeartbeatSecondsPathVar(HeartbeatSecondsPath):
    variable_sample: Final[VariableSample]

    def __init__(self, variable_sample: VariableSample):
        super().__init__(path=variable_sample.expression)
        self.variable_sample = variable_sample

    def _eval_seconds(self, env: Environment) -> int:
        self.variable_sample.eval(env=env)
        seconds = env.stack.pop()
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for HeartbeatSecondsPath, got '{seconds}' instead."
            )
        return seconds
