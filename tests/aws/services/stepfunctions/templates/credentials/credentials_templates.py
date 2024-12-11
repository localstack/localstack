import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class CredentialsTemplates(TemplateLoader):
    EMPTY_CREDENTIALS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/empty_credentials.json5"
    )
    INVALID_CREDENTIALS_FIELD: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/invalid_credentials_field.json5"
    )
    LAMBDA_TASK: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/lambda_task.json5")
    SERVICE_LAMBDA_INVOKE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/service_lambda_invoke.json5"
    )
    SERVICE_LAMBDA_INVOKE_RETRY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/service_lambda_invoke_retry.json5"
    )
    SFN_START_EXECUTION_SYNC_ROLE_ARN_JSONATA: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync_role_arn_jsonata.json5"
    )
    SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync_role_arn_path.json5"
    )
    SFN_START_EXECUTION_SYNC_ROLE_ARN_PATH_CONTEXT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync_role_arn_path_context.json5"
    )
    SFN_START_EXECUTION_SYNC_ROLE_ARN_VARIABLE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync_role_arn_variable.json5"
    )
    SFN_START_EXECUTION_SYNC_ROLE_ARN_INTRINSIC: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution_sync_role_arn_intrinsic.json5"
    )
