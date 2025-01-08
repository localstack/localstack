import abc
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    ExecutionFailedEventDetails,
    HistoryEventType,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name import (
    StatesErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.states_error_name_type import (
    StatesErrorNameType,
)
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.json_path import NoSuchJsonPathError


class EvalTimeoutError(TimeoutError):
    pass


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


class TimeoutSecondsJSONata(Timeout):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def is_default_value(self) -> bool:
        return False

    def _eval_seconds(self, env: Environment) -> int:
        self.string_jsonata.eval(env=env)
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        seconds = int(env.stack.pop())
        return seconds


class TimeoutSecondsPath(Timeout):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def is_default_value(self) -> bool:
        return False

    def _eval_seconds(self, env: Environment) -> int:
        try:
            self.string_sampler.eval(env=env)
        except NoSuchJsonPathError as no_such_json_path_error:
            json_path = no_such_json_path_error.json_path
            cause = f"Invalid path '{json_path}' : No results for path: $['{json_path[2:]}']"
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                    event_type=HistoryEventType.ExecutionFailed,
                    event_details=EventDetails(
                        executionFailedEventDetails=ExecutionFailedEventDetails(
                            error=StatesErrorNameType.StatesRuntime.to_name(), cause=cause
                        )
                    ),
                )
            )
        seconds = env.stack.pop()
        if not isinstance(seconds, int) and seconds <= 0:
            raise ValueError(
                f"Expected non-negative integer for TimeoutSecondsPath, got '{seconds}' instead."
            )
        return seconds
