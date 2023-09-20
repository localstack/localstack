from typing import Final, Optional, TypedDict

from localstack.services.stepfunctions.asl.component.eval_component import EvalComponent
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.csv_header_location import (
    CSVHeaderLocation,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.csv_headers import (
    CSVHeaders,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.input_type import (
    InputType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.reader_config.max_items_decl import (
    MaxItems,
    MaxItemsDecl,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class InputTypeOutput(str):
    CSV = "CSV"
    JSON = "JSON"


class CSVHeaderLocationOutput(str):
    FIRST_ROW = "FIRST_ROW"
    GIVEN = "GIVEN"


CSVHeadersOutput = list[str]
MaxItemsValueOutput = int


class ReaderConfigOutput(TypedDict):
    InputType: InputTypeOutput
    CSVHeaderLocation: CSVHeaderLocationOutput
    CSVHeaders: Optional[CSVHeadersOutput]
    MaxItemsValue: MaxItemsValueOutput


class ReaderConfig(EvalComponent):
    input_type: Final[InputType]
    max_items: Final[MaxItemsDecl]
    csv_header_location: Final[CSVHeaderLocation]
    csv_headers: Optional[CSVHeaders]

    def __init__(
        self,
        input_type: InputType,
        csv_header_location: CSVHeaderLocation,
        csv_headers: Optional[CSVHeaders],
        max_items: Optional[MaxItemsDecl],
    ):
        self.input_type = input_type
        self.max_items = max_items or MaxItems()
        self.csv_header_location = csv_header_location
        self.csv_headers = csv_headers
        # TODO: verify behaviours:
        #  - csv fields are declared with json input type
        #  - headers are declared with first_fow location set

    def _eval_body(self, env: Environment) -> None:
        self.max_items.eval(env=env)
        max_items_value: int = env.stack.pop()

        reader_config_output = ReaderConfigOutput(
            InputType=InputTypeOutput(self.input_type.input_type_value),
            MaxItemsValue=max_items_value,
        )
        if self.csv_header_location:
            reader_config_output[
                "CSVHeaderLocation"
            ] = self.csv_header_location.csv_header_location_value.value
        if self.csv_headers:
            reader_config_output["CSVHeaders"] = self.csv_headers.header_names
        env.stack.append(reader_config_output)
