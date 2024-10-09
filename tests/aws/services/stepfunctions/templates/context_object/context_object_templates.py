import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ContextObjectTemplates(TemplateLoader):
    CONTEXT_OBJECT_LITERAL_PLACEHOLDER = "%CONTEXT_OBJECT_LITERAL_PLACEHOLDER%"

    CONTEXT_OBJECT_INPUT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/context_object_input_path.json5"
    )
    CONTEXT_OBJECT_ITEMS_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/context_object_items_path.json5"
    )
    CONTEXT_OBJECT_OUTPUT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/context_object_output_path.json5"
    )
    CONTEXT_OBJECT_RESULT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/context_object_result_selector.json5"
    )
    CONTEXT_OBJECT_VARIABLE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/context_object_variable.json5"
    )
