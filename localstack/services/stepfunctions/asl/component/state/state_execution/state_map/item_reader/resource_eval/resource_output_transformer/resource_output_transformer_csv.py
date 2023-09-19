import csv
import io

from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.reader_config_decl import (
    CSVHeaderLocationOutput,
    ReaderConfigOutput,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class ResourceOutputTransformerCSV(ResourceOutputTransformer):
    def _eval_body(self, env: Environment) -> None:
        reader_config: ReaderConfigOutput = env.stack.pop()
        resource_value: str = env.stack.pop()

        csv_file = io.StringIO(resource_value)
        csv_reader = csv.reader(csv_file)

        # TODO check these scenarios:
        #     - [] duplicate headers in csv either given or first row
        #     - [] non str headers in given or first row
        #     - [] more headers than fields
        #     - [] more fields than headers
        match reader_config["CSVHeaderLocation"]:
            case CSVHeaderLocationOutput.FIRST_ROW:
                headers = next(csv_reader)
            case CSVHeaderLocationOutput.GIVEN:
                headers = reader_config["CSVHeaders"]
            case unknown:
                raise ValueError(f"Unknown CSVHeaderLocation value '{unknown}'.")

        transformed_outputs = list()
        for row in csv_reader:
            transformed_output = {header: row for header, row in zip(headers, row)}
            transformed_outputs.append(transformed_output)

        env.stack.append(transformed_outputs)
