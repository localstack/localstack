import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class CallbackTemplates(TemplateLoader):
    SQS_SUCCESS_ON_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_success_on_task_token.json5"
    )
    SQS_WAIT_FOR_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_wait_for_task_token.json5"
    )
