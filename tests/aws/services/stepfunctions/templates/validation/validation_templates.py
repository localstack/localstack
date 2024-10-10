import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ValidationTemplate(TemplateLoader):
    INVALID_BASE_NO_STARTAT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/invalid_base_no_startat.json5"
    )
    VALID_BASE_PASS: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/valid_base_pass.json5")
