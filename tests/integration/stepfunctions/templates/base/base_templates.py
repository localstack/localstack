import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class BaseTemplate(TemplateLoader):
    BASE_INVALID_DER: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/invalid_der.json5")
    BASE_PASS_RESULT: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/pass_result.json5")
    BASE_TASK_SEQ_2: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/task_seq_2.json5")
    BASE_WAIT_1_MIN: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/wait_1_min.json5")
