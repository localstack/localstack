import enum
from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component


class InputTypeValue(enum.Enum):
    """
    Represents the supported InputType values for ItemReader configurations.
    """

    # TODO: add support for MANIFEST InputTypeValue.
    CSV = "CSV"
    JSON = "JSON"


class InputType(Component):
    """
    "InputType" Specifies the type of Amazon S3 data source, such as CSV file, object, JSON file, or an
    Amazon S3 inventory list. In Workflow Studio, you can select an input type from the Amazon S3 item
    source dropdown list under the Item source field.
    """

    input_type_value: Final[InputTypeValue]

    def __init__(self, input_type: str):
        self.input_type_value = InputTypeValue(input_type)  # Pass error upstream.
