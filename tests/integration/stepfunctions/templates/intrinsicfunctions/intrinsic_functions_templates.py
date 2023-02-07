import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class IntrinsicFunctionTemplate(TemplateLoader):
    FUNCTION_INPUT_KEY: Final[str] = "FunctionInput"
    FUNCTION_OUTPUT_KEY: Final[str] = "FunctionResult"

    STRING_TO_JSON: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/string_to_json.json5")
    JSON_TO_STRING: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/json_to_string.json5")
