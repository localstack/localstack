import csv
import io
from collections import OrderedDict

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
    CSVHeaderLocationOutput,
    ReaderConfigOutput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails


class ResourceOutputTransformerCSV(ResourceOutputTransformer):
    def _eval_body(self, env: Environment) -> None:
        reader_config: ReaderConfigOutput = env.stack.pop()
        resource_value: str = env.stack.pop()

        csv_file = io.StringIO(resource_value)
        csv_reader = csv.reader(csv_file)

        match reader_config["CSVHeaderLocation"]:
            case CSVHeaderLocationOutput.FIRST_ROW:
                headers = next(csv_reader)
            case CSVHeaderLocationOutput.GIVEN:
                headers = reader_config["CSVHeaders"]
            case unknown:
                raise ValueError(f"Unknown CSVHeaderLocation value '{unknown}'.")

        if len(set(headers)) < len(headers):
            error_name = StatesErrorName(typ=StatesErrorNameType.StatesItemReaderFailed)
            failure_event = FailureEvent(
                env=env,
                error_name=error_name,
                event_type=HistoryEventType.TaskFailed,
                event_details=EventDetails(
                    mapRunFailedEventDetails=MapRunFailedEventDetails(
                        error=error_name.error_name,
                        cause="CSV headers cannot contain duplicates.",
                    )
                ),
            )
            raise FailureEventException(failure_event=failure_event)

        transformed_outputs = list()
        for row in csv_reader:
            transformed_output = dict()
            for i, header in enumerate(headers):
                transformed_output[header] = row[i] if i < len(row) else ""
            transformed_outputs.append(
                OrderedDict(
                    sorted(
                        transformed_output.items(), key=lambda item: (item[0].isalpha(), item[0])
                    )
                )
            )

        env.stack.append(transformed_outputs)
