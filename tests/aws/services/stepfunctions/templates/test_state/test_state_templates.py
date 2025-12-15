import os
from typing import Final

from tests.aws.services.stepfunctions.templates.template_loader import TemplateLoader

_THIS_FOLDER: Final[str] = os.path.dirname(os.path.realpath(__file__))


class TestStateTemplate(TemplateLoader):
    BASE_FAIL_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_fail_state.json5")
    BASE_SUCCEED_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_succeed_state.json5"
    )
    BASE_WAIT_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_wait_state.json5")
    BASE_PASS_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_pass_state.json5")
    BASE_CHOICE_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_choice_state.json5"
    )
    BASE_RESULT_PASS_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_result_pass_state.json5"
    )
    BASE_DYNAMODB_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_dynamodb_service_task_state.json5"
    )
    BASE_DYNAMODB_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_dynamodb_service_task_state.json5"
    )
    IO_DYNAMODB_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_dynamodb_service_task_state.json5"
    )
    IO_OUTPUT_PATH_DYNAMODB_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_output_path_dynamodb_service_task_state.json5"
    )

    IO_SQS_SERVICE_TASK_WAIT: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_sqs_service_task_wait.json5"
    )

    BASE_MAP_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/base_map_state.json5")
    BASE_MAP_STATE_WITH_RESULT_WRITER: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_result_writer.json5"
    )
    BASE_MAP_STATE_CATCH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_catch.json5"
    )
    BASE_MAP_STATE_RETRY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_retry.json5"
    )

    IO_PASS_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/io_pass_state.json5")
    IO_RESULT_PASS_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_result_pass_state.json5"
    )

    BASE_LAMBDA_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_task_state.json5"
    )
    BASE_LAMBDA_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_lambda_service_task_state.json5"
    )
    IO_LAMBDA_SERVICE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/io_lambda_service_task_state.json5"
    )
    BASE_EVENTS_PUT_EVENTS_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_events_put_events.json5"
    )
    BASE_SQS_SEND_MESSAGE_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_sqs_send_message.json5"
    )
    BASE_SFN_START_EXECUTION_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_sfn_start_execution.json5"
    )
    BASE_AWS_SDK_S3_GET_OBJECT_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_aws_api_s3_get_object.json5"
    )
    BASE_AWS_SDK_KMS_ENCRYPT_TASK_STATE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_aws_api_kms_encrypt.json5"
    )
    BASE_AWS_SDK_LAMBDA_GET_FUNCTION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_aws_api_lambda_get_function.json5"
    )

    BASE_TASK_STATE_RETRY: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_task_state_retry.json5"
    )
    BASE_TASK_STATE_CATCH: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_task_state_catch.json5"
    )

    MAP_TASK_STATE: Final[str] = os.path.join(_THIS_FOLDER, "statemachines/map_task_state.json5")


class TestStateMachineTemplate(TemplateLoader):
    BASE_MULTI_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_multi_state_machine.json5"
    )

    BASE_PASS_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_pass_state_machine.json5"
    )

    BASE_FAIL_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_fail_state_machine.json5"
    )

    BASE_MAP_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_machine.json5"
    )

    MAP_TASK_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_task_state_machine.json5"
    )

    MAP_ITEM_READER_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/map_item_reader_state_machine.json5"
    )

    # TODO The below state machines need to be snapshot and included in parity tests
    BASE_MAP_STATE_MACHINE_FAIL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_machine_fail.json5"
    )

    BASE_MAP_STATE_MACHINE_CHOICE_FAIL: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_map_state_machine_choice_fail.json5"
    )

    LOCALSTACK_BLOGPOST_SCENARIO_STATE_MACHINE: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/localstack_blogpost_scenario_state_machine.json5"
    )

    BASE_INVALID_STATE_DEFINITION: Final[str] = os.path.join(
        _THIS_FOLDER, "statemachines/base_invalid_state_definition.json5"
    )
