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
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringJSONata,
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str

DEFAULT_MAX_CONCURRENCY_VALUE: Final[int] = 0  # No limit.


class MaxConcurrencyDecl(EvalComponent, abc.ABC):
    @abc.abstractmethod
    def _eval_max_concurrency(self, env: Environment) -> int: ...

    def _eval_body(self, env: Environment) -> None:
        max_concurrency_value = self._eval_max_concurrency(env=env)
        env.stack.append(max_concurrency_value)


class MaxConcurrency(MaxConcurrencyDecl):
    max_concurrency_value: Final[int]

    def __init__(self, num: int = DEFAULT_MAX_CONCURRENCY_VALUE):
        super().__init__()
        self.max_concurrency_value = num

    def _eval_max_concurrency(self, env: Environment) -> int:
        return self.max_concurrency_value


class MaxConcurrencyJSONata(MaxConcurrencyDecl):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def _eval_max_concurrency(self, env: Environment) -> int:
        self.string_jsonata.eval(env=env)
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        seconds = int(env.stack.pop())
        return seconds


class MaxConcurrencyPath(MaxConcurrency):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        super().__init__()
        self.string_sampler = string_sampler

    def _eval_max_concurrency(self, env: Environment) -> int:
        self.string_sampler.eval(env=env)
        max_concurrency_value = env.stack.pop()

        if not isinstance(max_concurrency_value, int):
            try:
                max_concurrency_value = int(max_concurrency_value)
            except Exception:
                # Pass the wrong type forward.
                pass

        error_cause = None
        if not isinstance(max_concurrency_value, int):
            value_str = (
                to_json_str(max_concurrency_value)
                if not isinstance(max_concurrency_value, str)
                else max_concurrency_value
            )
            error_cause = f'The MaxConcurrencyPath field refers to value "{value_str}" which is not a valid integer: {self.string_sampler.literal_value}'
        elif max_concurrency_value < 0:
            error_cause = f"Expected non-negative integer for MaxConcurrency, got '{max_concurrency_value}' instead."

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

        return max_concurrency_value
