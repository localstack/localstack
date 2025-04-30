import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class MockedTemplates(TemplateLoader):
    LAMBDA_SQS_INTEGRATION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_sqs_integration.json5"
    )
