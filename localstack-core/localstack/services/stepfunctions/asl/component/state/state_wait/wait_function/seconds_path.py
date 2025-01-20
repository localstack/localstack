from typing import Any, Final

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
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.json_path import NoSuchJsonPathError


class SecondsPath(WaitFunction):
    # SecondsPath
    # A time, in seconds, to state_wait before beginning the state specified in the Next
    # field, specified using a path from the state's input data.
    # You must specify an integer value for this field.
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def _validate_seconds_value(self, env: Environment, seconds: Any):
        if isinstance(seconds, int) and seconds >= 0:
            return
        error_type = StatesErrorNameType.StatesRuntime

        assignment_description = f"{self.string_sampler.literal_value} == {seconds}"
        if not isinstance(seconds, int):
            cause = f"The SecondsPath parameter cannot be parsed as a long value: {assignment_description}"
        else:  # seconds < 0
            cause = (
                f"The SecondsPath parameter references a negative value: {assignment_description}"
            )

        raise FailureEventException(
            failure_event=FailureEvent(
                env=env,
                error_name=StatesErrorName(typ=error_type),
                event_type=HistoryEventType.ExecutionFailed,
                event_details=EventDetails(
                    executionFailedEventDetails=ExecutionFailedEventDetails(
                        error=error_type.to_name(), cause=cause
                    )
                ),
            )
        )

    def _get_wait_seconds(self, env: Environment) -> int:
        try:
            self.string_sampler.eval(env=env)
        except NoSuchJsonPathError as no_such_json_path_error:
            cause = f"The SecondsPath parameter does not reference an input value: {no_such_json_path_error.json_path}"
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
        self._validate_seconds_value(env=env, seconds=seconds)
        return seconds
