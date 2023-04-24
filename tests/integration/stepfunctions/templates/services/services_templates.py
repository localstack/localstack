import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ServicesTemplates(TemplateLoader):
    SQS_SEND_MESSAGE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/sqs_send_msg.json5")
