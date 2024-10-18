import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ErrorHandlingTemplate(TemplateLoader):
    # State Machines.
    AWS_SDK_TASK_FAILED_S3_LIST_OBJECTS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_task_error_s3_list_objects.json5"
    )

    AWS_SDK_TASK_FAILED_SECRETSMANAGER_CREATE_SECRET: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_task_error_secretsmanager_crate_secret.json5"
    )

    AWS_SDK_TASK_DYNAMODB_PUT_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_aws_sdk_dynamodb_put_item.json5"
    )

    AWS_SERVICE_DYNAMODB_PUT_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_dynamodb_put_item.json5"
    )

    AWS_LAMBDA_INVOKE_CATCH_UNKNOWN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_invoke_catch_unknown.json5"
    )

    AWS_LAMBDA_INVOKE_CATCH_RELEVANT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_lambda_invoke_catch_relevant.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_ALL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_all.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_ALL_OUTPUT_PATH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_all_output_path.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_DATA_LIMIT_EXCEEDED: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_data_limit_exceeded.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_UNKNOWN: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_unknown.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_TIMEOUT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_timeout.json5"
    )

    AWS_SERVICE_LAMBDA_INVOKE_CATCH_RELEVANT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_lambda_invoke_catch_relevant.json5"
    )

    AWS_SERVICE_SQS_SEND_MSG_CATCH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/task_service_sqs_send_msg_catch.json5"
    )

    AWS_SERVICE_SQS_SEND_MSG_CATCH_TOKEN_FAILURE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_service_sqs_send_msg_catch_token_failure.json5"
    )

    # Lambda Functions.
    LAMBDA_FUNC_LARGE_OUTPUT_STRING: Final[str] = os.path.join(
        _THIS_FOLDER, "lambdafunctions/large_output_string.py"
    )
    LAMBDA_FUNC_RAISE_EXCEPTION: Final[str] = os.path.join(
        _THIS_FOLDER, "lambdafunctions/raise_exception.py"
    )
