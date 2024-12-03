import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class OutputTemplates(TemplateLoader):
    BASE_EMPTY = os.path.join(_THIS_FOLDER, "statemachines/base_empty.json5")
    BASE_LITERALS = os.path.join(_THIS_FOLDER, "statemachines/base_literals.json5")
    BASE_EXPR = os.path.join(_THIS_FOLDER, "statemachines/base_expr.json5")
    BASE_DIRECT_EXPR = os.path.join(_THIS_FOLDER, "statemachines/base_direct_expr.json5")
    BASE_LAMBDA = os.path.join(_THIS_FOLDER, "statemachines/base_lambda.json5")
    BASE_TASK_LAMBDA = os.path.join(_THIS_FOLDER, "statemachines/base_task_lambda.json5")
    BASE_OUTPUT_ANY = os.path.join(_THIS_FOLDER, "statemachines/base_output_any.json5")
