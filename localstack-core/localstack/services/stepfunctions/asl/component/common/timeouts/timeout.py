import abc
from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.utils.json_path import extract_json


class Timeout(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def is_default_value(self) -> bool: ...

    @abc.abstractmethod
    def _eval_seconds(self, env: Environment) -> int: ...

    def _eval_body(self, env: Environment) -> None:
        seconds = self._eval_seconds(env=env)
        env.stack.append(seconds)


class TimeoutSeconds(Timeout):
    DEFAULT_TIMEOUT_SECONDS: Final[int] = 99999999

    def __init__(self, timeout_seconds: int, is_default: Optional[bool] = None):
        if not isinstance(timeout_seconds, int) and timeout_seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for TimeoutSeconds, got '{timeout_seconds}' instead."
            )
        self.timeout_seconds: Final[int] = timeout_seconds
        self.is_default: Optional[bool] = is_default

    def is_default_value(self) -> bool:
        if self.is_default is not None:
            return self.is_default
        return self.timeout_seconds == self.DEFAULT_TIMEOUT_SECONDS

    def _eval_seconds(self, env: Environment) -> int:
        return self.timeout_seconds


class TimeoutSecondsPath(Timeout):
    def __init__(self, path: str):
        self.path: Final[str] = path

    @classmethod
    def from_raw(cls, path: str):
        return cls(path=path)

    def is_default_value(self) -> bool:
        return False

    def _eval_seconds(self, env: Environment) -> int:
        inp = env.stack[-1]
        seconds = extract_json(self.path, inp)
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for TimeoutSecondsPath, got '{seconds}' instead."
            )
        return seconds


class EvalTimeoutError(TimeoutError):
    pass
