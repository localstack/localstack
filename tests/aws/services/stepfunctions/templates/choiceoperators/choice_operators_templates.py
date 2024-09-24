import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ChoiceOperatorTemplate(TemplateLoader):
    COMPARISON_OPERATOR_PLACEHOLDER = "%ComparisonOperatorType%"
    VARIABLE_KEY: Final[str] = "Variable"
    VALUE_KEY: Final[str] = "Value"
    VALUE_PLACEHOLDER = '"$.Value"'
    TEST_RESULT_KEY: Final[str] = "TestResult"

    BASE_TEMPLATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/template.json5")
