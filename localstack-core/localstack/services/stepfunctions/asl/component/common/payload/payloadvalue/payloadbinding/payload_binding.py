import abc
from typing import Any, Final

from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
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
from localstack.services.stepfunctions.asl.component.common.payload.payloadvalue.payload_value import (
    PayloadValue,
)
from localstack.services.stepfunctions.asl.component.common.string.string import (
    StringJsonPath,
    StringSampler,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class PayloadBinding(PayloadValue, abc.ABC):
    field: Final[str]

    def __init__(self, field: str):
        self.field = field

    @abc.abstractmethod
    def _eval_val(self, env: Environment) -> Any: ...

    def _eval_body(self, env: Environment) -> None:
        cnt: dict = env.stack.pop()
        val = self._eval_val(env=env)
        cnt[self.field] = val
        env.stack.append(cnt)


class PayloadBindingSample(PayloadBinding):
    string_sampler: Final[StringSampler]

    def __init__(self, field: str, string_sampler: StringSampler):
        super().__init__(field=field)
        self.string_sampler = string_sampler

    def _eval_val(self, env: Environment) -> Any:
        try:
            self.string_sampler.eval(env=env)
        except RuntimeError as runtime_error:
            if isinstance(self.string_sampler, StringJsonPath):
                failure_event = FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                    event_type=HistoryEventType.TaskFailed,
                    event_details=EventDetails(
                        taskFailedEventDetails=TaskFailedEventDetails(
                            error=StatesErrorNameType.StatesRuntime.to_name(),
                            cause=f"The JSONPath {self.string_sampler.literal_value} specified for the field {self.field}.$ could not be found in the input {to_json_str(env.stack[-1])}",
                        )
                    ),
                )
                raise FailureEventException(failure_event=failure_event)
            else:
                raise runtime_error

        value = env.stack.pop()
        return value


class PayloadBindingValue(PayloadBinding):
    payload_value: Final[PayloadValue]

    def __init__(self, field: str, payload_value: PayloadValue):
        super().__init__(field=field)
        self.payload_value = payload_value

    def _eval_val(self, env: Environment) -> Any:
        self.payload_value.eval(env)
        val: Any = env.stack.pop()
        return val
