import json

from localstack.aws.api.stepfunctions import HistoryEventType, MapRunFailedEventDetails
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
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    ReaderConfigOutput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class ResourceOutputTransformerJson(ResourceOutputTransformer):
    def _eval_body(self, env: Environment) -> None:
        _: ReaderConfigOutput = (
            env.stack.pop()
        )  # Not used, but expected by workflow (hence should consume the stack).
        resource_value: str = env.stack.pop()

        json_list = json.loads(resource_value)

        if not isinstance(json_list, list):
            error_name = StatesErrorName(typ=StatesErrorNameType.StatesItemReaderFailed)
            failure_event = FailureEvent(
                env=env,
                error_name=error_name,
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    mapRunFailedEventDetails=MapRunFailedEventDetails(
                        error=error_name.error_name,
                        cause="Attempting to map over non-iterable node.",
                    )
                ),
            )
            raise FailureEventException(failure_event=failure_event)

        env.stack.append(json_list)
