from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.input_type import (
    InputType,
    InputTypeValue,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer import (
    ResourceOutputTransformer,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer_csv import (
    ResourceOutputTransformerCSV,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_output_transformer.resource_output_transformer_json import (
    ResourceOutputTransformerJson,
)


def resource_output_transformer_for(input_type: InputType) -> ResourceOutputTransformer:
    match input_type.input_type_value:
        case InputTypeValue.CSV:
            return ResourceOutputTransformerCSV()
        case InputTypeValue.JSON:
            return ResourceOutputTransformerJson()
        case unknown:
            raise ValueError(f"Unknown InputType value: '{unknown}'.")
