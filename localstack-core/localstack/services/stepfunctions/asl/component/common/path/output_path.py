from typing import Final, Optional

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
from localstack.services.stepfunctions.asl.component.common.string.string_expression import (
    StringSampler,
)
from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.services.stepfunctions.asl.utils.json_path import NoSuchJsonPathError


class OutputPath(EvalComponent):
    string_sampler: Final[Optional[StringSampler]]

    def __init__(self, string_sampler: Optional[StringSampler]):
        self.string_sampler = string_sampler

    def _eval_body(self, env: Environment) -> None:
        if self.string_sampler is None:
            env.states.reset(input_value=dict())
            return
        try:
            self.string_sampler.eval(env=env)
        except NoSuchJsonPathError as no_such_json_path_error:
            json_path = no_such_json_path_error.json_path
            cause = f"Invalid path '{json_path}' : No results for path: $['{json_path[2:]}']"
            raise FailureEventException(
                failure_event=FailureEvent(
                    env=env,
                    error_name=StatesErrorName(typ=StatesErrorNameType.StatesRuntime),
                    event_type=HistoryEventType.TaskFailed,
                    event_details=EventDetails(
                        taskFailedEventDetails=TaskFailedEventDetails(
                            error=StatesErrorNameType.StatesRuntime.to_name(), cause=cause
                        )
                    ),
                )
            )
        output_value = env.stack.pop()
        env.states.reset(output_value)
