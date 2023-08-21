import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class CallbackTemplates(TemplateLoader):
    SFN_START_EXECUTION_SYNC: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync.json5"
    )
    SFN_START_EXECUTION_SYNC2: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync2.json5"
    )
    SQS_SUCCESS_ON_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_success_on_task_token.json5"
    )
    SQS_FAILURE_ON_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_failure_on_task_token.json5"
    )
    SQS_WAIT_FOR_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_wait_for_task_token.json5"
    )
    SQS_WAIT_FOR_TASK_TOKEN_WITH_TIMEOUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_wait_for_task_token_with_timeout.json5"
    )
    SQS_HEARTBEAT_SUCCESS_ON_TASK_TOKEN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sqs_hearbeat_success_on_task_token.json5"
    )
