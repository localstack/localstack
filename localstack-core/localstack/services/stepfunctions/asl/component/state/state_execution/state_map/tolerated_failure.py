import abc
from typing import Final

from localstack.aws.api.stepfunctions import ExecutionFailedEventDetails, HistoryEventType
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
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str
from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils

TOLERATED_FAILURE_COUNT_MIN: Final[int] = 0
TOLERATED_FAILURE_COUNT_DEFAULT: Final[int] = 0
TOLERATED_FAILURE_PERCENTAGE_MIN: Final[float] = 0.0
TOLERATED_FAILURE_PERCENTAGE_DEFAULT: Final[float] = 0.0
TOLERATED_FAILURE_PERCENTAGE_MAX: Final[float] = 100.0


class ToleratedFailureCountDecl(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _eval_tolerated_failure_count(self, env: Environment) -> int: ...

    def _eval_body(self, env: Environment) -> None:
        tolerated_failure_count = self._eval_tolerated_failure_count(env=env)
        env.stack.append(tolerated_failure_count)


class ToleratedFailureCount(ToleratedFailureCountDecl):
    tolerated_failure_count: Final[int]

    def __init__(self, tolerated_failure_count: int = TOLERATED_FAILURE_COUNT_DEFAULT):
        self.tolerated_failure_count = tolerated_failure_count

    def _eval_tolerated_failure_count(self, env: Environment) -> int:
        return self.tolerated_failure_count


class ToleratedFailureCountPath(ToleratedFailureCountDecl):
    tolerated_failure_count_path: Final[str]

    def __init__(self, tolerated_failure_count_path: str):
        self.tolerated_failure_count_path = tolerated_failure_count_path

    def _eval_tolerated_failure_count(self, env: Environment) -> int:
        inp = env.stack[-1]
        tolerated_failure_count = JSONPathUtils.extract_json(self.tolerated_failure_count_path, inp)

        error_cause = None
        if not isinstance(tolerated_failure_count, int):
            value_str = (
                to_json_str(tolerated_failure_count)
                if not isinstance(tolerated_failure_count, str)
                else tolerated_failure_count
            )
            error_cause = (
                f'The ToleratedFailureCountPath field refers to value "{value_str}" '
                f"which is not a valid integer: {self.tolerated_failure_count_path}"
            )

        elif tolerated_failure_count < TOLERATED_FAILURE_COUNT_MIN:
            error_cause = "ToleratedFailureCount cannot be negative."

        if error_cause is not None:
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                    event_type=HistoryEventType.ExecutionFailed,
                    event_details=EventDetails(
                        executionFailedEventDetails=ExecutionFailedEventDetails(
                            error=StatesErrorNameType.StatesRuntime.to_name(), cause=error_cause
                        )
                    ),
                )
            )

        return tolerated_failure_count


class ToleratedFailurePercentageDecl(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _eval_tolerated_failure_percentage(self, env: Environment) -> float: ...

    def _eval_body(self, env: Environment) -> None:
        tolerated_failure_percentage = self._eval_tolerated_failure_percentage(env=env)
        env.stack.append(tolerated_failure_percentage)


class ToleratedFailurePercentage(ToleratedFailurePercentageDecl):
    tolerated_failure_percentage: Final[float]

    def __init__(self, tolerated_failure_percentage: float = TOLERATED_FAILURE_PERCENTAGE_DEFAULT):
        self.tolerated_failure_percentage = tolerated_failure_percentage

    def _eval_tolerated_failure_percentage(self, env: Environment) -> float:
        return self.tolerated_failure_percentage


class ToleratedFailurePercentagePath(ToleratedFailurePercentageDecl):
    tolerate_failure_percentage_path: Final[str]

    def __init__(self, tolerate_failure_percentage_path: str):
        self.tolerate_failure_percentage_path = tolerate_failure_percentage_path

    def _eval_tolerated_failure_percentage(self, env: Environment) -> float:
        inp = env.stack[-1]
        tolerated_failure_percentage = JSONPathUtils.extract_json(
            self.tolerate_failure_percentage_path, inp
        )

        if isinstance(tolerated_failure_percentage, int):
            tolerated_failure_percentage = float(tolerated_failure_percentage)

        error_cause = None
        if not isinstance(tolerated_failure_percentage, float):
            value_str = (
                to_json_str(tolerated_failure_percentage)
                if not isinstance(tolerated_failure_percentage, str)
                else tolerated_failure_percentage
            )
            error_cause = (
                f'The ToleratedFailurePercentagePath field refers to value "{value_str}" '
                f"which is not a valid float: {self.tolerate_failure_percentage_path}"
            )
        elif (
            not TOLERATED_FAILURE_PERCENTAGE_MIN
            <= tolerated_failure_percentage
            <= TOLERATED_FAILURE_PERCENTAGE_MAX
        ):
            error_cause = "ToleratedFailurePercentage must be between 0 and 100."

        if error_cause is not None:
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                    event_type=HistoryEventType.ExecutionFailed,
                    event_details=EventDetails(
                        executionFailedEventDetails=ExecutionFailedEventDetails(
                            error=StatesErrorNameType.StatesRuntime.to_name(), cause=error_cause
                        )
                    ),
                )
            )

        return tolerated_failure_percentage
