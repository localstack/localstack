import os
from typing import Final

from tests.integration.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ErrorHandlingTemplate(TemplateLoader):

    AWS_SDK_TASK_FAILED_S3_LIST_OBJECTS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_task_error_s3_list_objects.json5"
    )

    AWS_SDK_TASK_FAILED_SECRETSMANAGER_CREATE_SECRET: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_task_error_secretsmanager_crate_secret.json5"
    )
