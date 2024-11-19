import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class EvaluateJsonataTemplate(TemplateLoader):
    JSONATA_NUMBER_EXPRESSION = "{% $variable := 1 %}"
    JSONATA_ARRAY_ELEMENT_EXPRESSION_DOUBLE_QUOTES = [1, "{% $number('2') %}", 3]
    JSONATA_ARRAY_ELEMENT_EXPRESSION = [1, '{% $number("2") %}', 3]
    JSONATA_STATE_INPUT_EXPRESSION = "{% $states.input.input_value %}"

    BASE_MAP = os.path.join(_THIS_FOLDER, "statemachines/base_map.json5")
    BASE_TASK = os.path.join(_THIS_FOLDER, "statemachines/base_task.json5")
