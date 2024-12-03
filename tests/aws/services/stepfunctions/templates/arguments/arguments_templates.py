import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ArgumentTemplates(TemplateLoader):
    BASE_LAMBDA_EMPTY = os.path.join(_THIS_FOLDER, "statemachines/base_lambda_empty.json5")
    BASE_LAMBDA_EMPTY_GLOBAL_QL_JSONATA = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_empty_global_ql_jsonata.json5"
    )
    BASE_LAMBDA_EXPRESSION = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_expressions.json5"
    )
    BASE_LAMBDA_LITERALS = os.path.join(_THIS_FOLDER, "statemachines/base_lambda_literals.json5")
