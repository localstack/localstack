import datetime
import re
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
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringExpression,
    StringLiteral,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails

TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%SZ"
# TODO: could be a bit more exact (e.g. 90 shouldn't be a valid minute)
TIMESTAMP_PATTERN: Final[str] = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"


def parse_timestamp(timestamp: str) -> datetime.datetime:
    # TODO: need to fix this like we're doing for TimestampPath & add a test
    return datetime.datetime.strptime(timestamp, TIMESTAMP_FORMAT)


class Timestamp(WaitFunction):
    string: Final[StringExpression]

    def __init__(self, string: StringExpression):
        self.string = string
        # If it's a string literal, assert it encodes a timestamp
        if isinstance(string, StringLiteral):
            parse_timestamp(string.literal_value)

    def _get_wait_seconds(self, env: Environment) -> int:
        self.string.eval(env=env)
        timestamp_str: str = env.stack.pop()
        timestamp_datetime = parse_timestamp(timestamp_str)
        delta = timestamp_datetime - datetime.datetime.now()
        delta_sec = int(delta.total_seconds())
        return delta_sec


class TimestampPath(Timestamp):
    def _create_failure_event(self, env: Environment, timestamp_str: str) -> FailureEvent:
        return FailureEvent(
            env=env,
            error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
            event_type=HistoryEventType.ExecutionFailed,
            event_details=EventDetails(
                executionFailedEventDetails=ExecutionFailedEventDetails(
                    error=StatesErrorNameType.StatesRuntime.to_name(),
                    cause=f"The TimestampPath parameter does not reference a valid ISO-8601 extended offset date-time format string: {self.string.literal_value} == {timestamp_str}",
                )
            ),
        )

    def _compute_delta_seconds(self, env: Environment, timestamp_str: str):
        try:
            if not re.match(TIMESTAMP_PATTERN, timestamp_str):
                raise FailureEventException(self._create_failure_event(env, timestamp_str))

            # anything lower than seconds is truncated
            processed_timestamp = timestamp_str.rsplit(".", 2)[0]
            # add back the "Z" suffix if we removed it
            if not processed_timestamp.endswith("Z"):
                processed_timestamp = f"{processed_timestamp}Z"
            timestamp = datetime.datetime.strptime(processed_timestamp, TIMESTAMP_FORMAT)
        except Exception:
            raise FailureEventException(self._create_failure_event(env, timestamp_str))

        delta = timestamp - datetime.datetime.now()
        delta_sec = int(delta.total_seconds())
        return delta_sec

    def _get_wait_seconds(self, env: Environment) -> int:
        self.string.eval(env=env)
        timestamp_str: str = env.stack.pop()
        delta_sec = self._compute_delta_seconds(env=env, timestamp_str=timestamp_str)
        return delta_sec
