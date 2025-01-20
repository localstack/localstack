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


class MaxItemsDecl(EvalComponent, abc.ABC):
    """
    "MaxItems": Limits the number of data items passed to the Map state. For example, suppose that you provide a
    CSV file that contains 1000 rows and specify a limit of 100. Then, the interpreter passes only 100 rows to the
    Map state. The Map state processes items in sequential order, starting after the header row.
    Currently, you can specify a limit of up to 100,000,000
    """

    MAX_VALUE: Final[int] = 100_000_000

    def _clip_value(self, value: int) -> int:
        if value == 0:
            return self.MAX_VALUE
        return min(value, self.MAX_VALUE)

    @abc.abstractmethod
    def _get_value(self, env: Environment) -> int: ...

    def _eval_body(self, env: Environment) -> None:
        max_items: int = self._get_value(env=env)
        max_items = self._clip_value(max_items)
        env.stack.append(max_items)


class MaxItemsInt(MaxItemsDecl):
    max_items: Final[int]

    def __init__(self, max_items: int = MaxItemsDecl.MAX_VALUE):
        if max_items < 0 or max_items > MaxItemsInt.MAX_VALUE:
            raise ValueError(
                f"MaxItems value MUST be a non-negative integer "
                f"non greater than '{MaxItemsInt.MAX_VALUE}', got '{max_items}'."
            )
        self.max_items = max_items

    def _get_value(self, env: Environment) -> int:
        return self.max_items


class MaxItemsStringJSONata(MaxItemsDecl):
    string_jsonata: Final[StringJSONata]

    def __init__(self, string_jsonata: StringJSONata):
        super().__init__()
        self.string_jsonata = string_jsonata

    def _get_value(self, env: Environment) -> int:
        # TODO: add snapshot tests to verify AWS's behaviour about non integer values.
        self.string_jsonata.eval(env=env)
        max_items: int = int(env.stack.pop())
        return max_items


class MaxItemsPath(MaxItemsDecl):
    string_sampler: Final[StringSampler]

    def __init__(self, string_sampler: StringSampler):
        self.string_sampler = string_sampler

    def _validate_value(self, env: Environment, value: int) -> None:
        if not isinstance(value, int):
            # TODO: Note, this error appears to be validated at a earlier stage in AWS Step Functions, unlike the
            #  negative integer check that is validated at this exact depth.
            error_typ = StatesErrorNameType.StatesItemReaderFailed
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=error_typ),
                    event_type=HistoryEventType.ExecutionFailed,
                    event_details=EventDetails(
                        executionFailedEventDetails=ExecutionFailedEventDetails(
                            error=error_typ.to_name(),
                            cause=(
                                f"The MaxItemsPath field refers to value '{value}' "
                                f"which is not a valid integer: {self.string_sampler.literal_value}"
                            ),
                        )
                    ),
                )
            )
        if value < 0:
            error_typ = StatesErrorNameType.StatesItemReaderFailed
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=error_typ),
                    event_type=HistoryEventType.MapRunFailed,
                    event_details=EventDetails(
                        executionFailedEventDetails=ExecutionFailedEventDetails(
                            error=error_typ.to_name(),
                            cause="field MaxItems must be positive",
                        )
                    ),
                )
            )

    def _get_value(self, env: Environment) -> int:
        self.string_sampler.eval(env=env)
        max_items = env.stack.pop()
        if isinstance(max_items, str):
            try:
                max_items = int(max_items)
            except Exception:
                # Pass incorrect type forward for validation and error reporting
                pass
        self._validate_value(env=env, value=max_items)
        return max_items
