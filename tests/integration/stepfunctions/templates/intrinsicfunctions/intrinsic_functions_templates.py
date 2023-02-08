import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class IntrinsicFunctionTemplate(TemplateLoader):
    FUNCTION_INPUT_KEY: Final[str] = "FunctionInput"
    FUNCTION_OUTPUT_KEY: Final[str] = "FunctionResult"

    STRING_TO_JSON: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/string_to_json.json5")
    JSON_TO_STRING: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/json_to_string.json5")
    FORMAT_1: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/format_1.json5")
    FORMAT_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/format_2.json5")
    ARRAY_0: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array_0.json5")
    ARRAY_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array_2.json5")
    UUID: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/uuid.json5")
    ARRAY_PARTITION: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array_partition.json5")
    ARRAY_CONTAINS: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array_contains.json5")
    ARRAY_RANGE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/array_range.json5")
