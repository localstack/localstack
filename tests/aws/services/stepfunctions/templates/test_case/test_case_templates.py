import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class TestCaseTemplate(TemplateLoader):
    BASE_PASS_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_pass_state.json5")
