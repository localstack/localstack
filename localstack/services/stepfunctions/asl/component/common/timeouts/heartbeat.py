import abc
from typing import Final

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils


class Heartbeat(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _eval_seconds(self, env: Environment) -> int:
        ...

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


class HeartbeatSecondsPath(Heartbeat):
    def __init__(self, path: str):
        self.path: Final[str] = path

    @classmethod
    def from_raw(cls, path: str):
        return cls(path=path)

    def _eval_seconds(self, env: Environment) -> int:
        seconds = JSONPathUtils.extract_json(self.path, env.inp)
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for HeartbeatSecondsPath, got '{seconds}' instead."
            )
        return seconds
