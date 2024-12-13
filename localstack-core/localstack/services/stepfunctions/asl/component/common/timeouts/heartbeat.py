import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment


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
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def _eval_seconds(self, env: Environment) -> int:
        self.string_jsonata.eval(env=env)
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        seconds = int(env.stack.pop())
        return seconds


class HeartbeatSecondsPath(Heartbeat):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def _eval_seconds(self, env: Environment) -> int:
        self.string_sampler.eval(env=env)
        seconds = env.stack.pop()
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for HeartbeatSecondsPath, got '{seconds}' instead."
            )
        return seconds
