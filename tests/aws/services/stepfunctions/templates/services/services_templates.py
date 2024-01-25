import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class ServicesTemplates(TemplateLoader):
    # State Machines.
    AWSSDK_LIST_SECRETS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_secrestsmaager_list_secrets.json5"
    )
    AWS_SDK_DYNAMODB_PUT_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_dynamodb_put_get_item.json5"
    )
    AWS_SDK_DYNAMODB_PUT_DELETE_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_dynamodb_put_delete_item.json5"
    )
    AWS_SDK_DYNAMODB_PUT_UPDATE_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_dynamodb_put_update_get_item.json5"
    )
    AWS_SDK_SFN_START_EXECUTION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/aws_sdk_sfn_start_execution.json5"
    )
    API_GATEWAY_INVOKE_BASE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/api_gateway_invoke_base.json5"
    )
    API_GATEWAY_INVOKE_WITH_BODY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/api_gateway_invoke_with_body.json5"
    )
    API_GATEWAY_INVOKE_WITH_QUERY_PARAMETERS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/api_gateway_invoke_with_query_parameters.json5"
    )
    EVENTS_PUT_EVENTS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/events_put_events.json5"
    )
    SQS_SEND_MESSAGE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/sqs_send_msg.json5")
    SNS_PUBLISH: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/sns_publish.json5")
    SNS_PUBLISH_MESSAGE_ATTRIBUTES: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sns_publish_message_attributes.json5"
    )
    LAMBDA_INVOKE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/lambda_invoke.json5")
    LAMBDA_INVOKE_PIPE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_invoke_pipe.json5"
    )
    LAMBDA_INVOKE_RESOURCE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_invoke_resource.json5"
    )
    LAMBDA_INVOKE_LOG_TYPE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_invoke_log_type.json5"
    )
    LAMBDA_LIST_FUNCTIONS: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/lambda_list_functions.json5"
    )
    LAMBDA_INPUT_PARAMETERS_FILTER: Final[str] = os.path.join(
        _THIS_FOLDER, "../services/statemachines/lambda_input_parameters_filter.json5"
    )
    SFN_START_EXECUTION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/sfn_start_execution.json5"
    )
    DYNAMODB_PUT_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/dynamodb_put_get_item.json5"
    )
    DYNAMODB_PUT_DELETE_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/dynamodb_put_delete_item.json5"
    )
    DYNAMODB_PUT_UPDATE_GET_ITEM: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/dynamodb_put_update_get_item.json5"
    )
    # Lambda Functions.
    LAMBDA_ID_FUNCTION: Final[str] = os.path.join(_THIS_FOLDER, "lambdafunctions/id_function.py")
    LAMBDA_RETURN_BYTES_STR: Final[str] = os.path.join(
        _THIS_FOLDER, "lambdafunctions/return_bytes_str.py"
    )
