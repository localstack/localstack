import abc
import copy
from typing import Any, Final

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
    FailureEventException,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class MockedResponse(EvalComponent, abc.ABC):
    range_start: Final[int]
    range_end: Final[int]

    def __init__(self, range_start: int, range_end: int):
        super().__init__()
        if range_start < 0 or range_end < 0:
            raise ValueError(
                f"Invalid range: both '{range_start}' and '{range_end}' must be positive integers."
            )
        if range_start != range_end and range_end < range_start + 1:
            raise ValueError(
                f"Invalid range: values must be equal or '{range_start}' "
                f"must be at least one greater than '{range_end}'."
            )
        self.range_start = range_start
        self.range_end = range_end


class MockedResponseReturn(MockedResponse):
    payload: Final[dict[Any, Any]]

    def __init__(self, range_start: int, range_end: int, payload: dict[Any, Any]):
        super().__init__(range_start=range_start, range_end=range_end)
        self.payload = payload

    def _eval_body(self, env: Environment) -> None:
        payload_copy = copy.deepcopy(self.payload)
        env.stack.append(payload_copy)


class MockedResponseThrow(MockedResponse):
    error: Final[str]
    cause: Final[str]

    def __init__(self, range_start: int, range_end: int, error: str, cause: str):
        super().__init__(range_start=range_start, range_end=range_end)
        self.error = error
        self.cause = cause

    def _eval_body(self, env: Environment) -> None:
        task_failed_event_details = TaskFailedEventDetails(error=self.error, cause=self.cause)
        error_name = CustomErrorName(self.error)
        failure_event = FailureEvent(
            env=env,
            error_name=error_name,
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(taskFailedEventDetails=task_failed_event_details),
        )
        raise FailureEventException(failure_event=failure_event)
