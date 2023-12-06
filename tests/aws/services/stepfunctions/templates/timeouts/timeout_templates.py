import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class TimeoutTemplates(TemplateLoader):
    # State Machines.
    LAMBDA_WAIT_WITH_TIMEOUT_SECONDS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_wait_with_timeout_seconds.json5"
    )
    SERVICE_LAMBDA_WAIT_WITH_TIMEOUT_SECONDS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/service_lambda_wait_with_timeout_seconds.json5"
    )
    SERVICE_LAMBDA_MAP_FUNCTION_INVOKE_WITH_TIMEOUT_SECONDS: Final[str] = os.path.join(
        _THIS_FOLDER,
        "statemachines/service_lambda_map_function_invoke_with_timeout_seconds.json5",
    )
    SERVICE_LAMBDA_MAP_FUNCTION_INVOKE_WITH_TIMEOUT_SECONDS_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/service_lambda_wait_with_timeout_seconds_path.json5"
    )
    SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/service_sqs_send_and_wait_for_task_token_with_heartbeat.json5"
    )
    SERVICE_SQS_SEND_AND_WAIT_FOR_TASK_TOKEN_WITH_HEARTBEAT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER,
        "statemachines/service_sqs_send_and_wait_for_task_token_with_heartbeat_path.json5",
    )

    # Lambda Functions.
    LAMBDA_WAIT_60_SECONDS: Final[str] = os.path.join(
        _THIS_FOLDER, "lambdafunctions/wait_60_seconds.py"
    )
