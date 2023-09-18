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
    _input_type: Final[InputType]
    _max_items: Final[MaxItemsDecl]
    _csv_header_location: Final[CSVHeaderLocation]
    _csv_headers: Optional[CSVHeaders]

    def __init__(
        self,
        input_type: InputType,
        csv_header_location: CSVHeaderLocation,
        csv_headers: Optional[CSVHeaders],
        max_items: Optional[MaxItemsDecl],
    ):
        self._input_type = input_type
        self._max_items = max_items or MaxItems()
        self._csv_header_location = csv_header_location
        self._csv_headers = csv_headers

    def _eval_body(self, env: Environment) -> None:
        self._max_items.eval(env=env)
        max_items_value: int = env.stack.pop()

        reader_config_output = ReaderConfigOutput(
            InputType=InputTypeOutput(self._input_type.input_type_value),
            MaxItemsValue=max_items_value,
            CSVHeaderLocation=CSVHeaderLocationOutput(
                self._csv_header_location.csv_header_location_value
            ),
            CSVHeaders=self._csv_headers.header_names,
        )
        env.stack.append(reader_config_output)
