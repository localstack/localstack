import json

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestFieldValidationModePresent:
    EVENTBRIDGE_VALIDATION_PASS_FIELDS_NOT_IN_SPEC = [
        pytest.param({"random": "json"}, id="field_not_part_of_api_spec"),
        pytest.param({}, id="empty_json"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", EVENTBRIDGE_VALIDATION_PASS_FIELDS_NOT_IN_SPEC)
    def test_present_mode_mock_result_field_not_in_api_spec(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        """
        Only fields from the API spec are validated
        """
        template = TST.load_sfn_template(TST.BASE_EVENTS_PUT_EVENTS_TASK_STATE)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": "detail",
                "DetailType": "detail_type",
                "Source": "source",
            },
        ]
        exec_input = json.dumps({"Entries": entries})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    EVENTBRIDGE_VAlIDATION_ERRORS = [
        pytest.param(
            {"Entries": "Entries value should have been a list of entry objects"},
            id="wrong_type_top_level_field",
        ),
        pytest.param(
            {
                "Entries": [
                    {"EventId": ["EventId value should have been a string not a list of strings"]}
                ]
            },
            id="wrong_type_nested_field",
        ),
        pytest.param(
            {
                "Entries": [
                    {"EventId": "First eventId has correct type: string"},
                    {"EventId": ["Second eventId has incorrect type: array"]},
                ]
            },
            id="wrong_type_2nd_array_element",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", EVENTBRIDGE_VAlIDATION_ERRORS)
    def test_present_mode_eventbridge_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_EVENTS_PUT_EVENTS_TASK_STATE)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": "detail",
                "DetailType": "detail_type",
                "Source": "source",
            },
        ]
        exec_input = json.dumps({"Entries": entries})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    SFN_MALFORMED_RESULTS_ALLOWED_IN_PRESENT_MODE = [
        pytest.param(
            {},
            id="missing_required_fields",  # not validated in PRESENT mode
        ),
        pytest.param(
            {"executionArn": "stringValueExecutionArn", "startDate": "stringValueStartDate"},
            id="field_name_not_in_sfn_case",  # should be treated as unknown field
            marks=pytest.mark.skipif(
                condition=not is_aws_cloud(),
                reason="in LocalStack mock field names are normalized whereas in AWS they are not",
                # TODO analyse if this normalization can be reasonable fixed - mock is only applied to StateTaskService._eval_service_task, all before_ and after_ methods are still executed, maybe it is not needed
            ),
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", SFN_MALFORMED_RESULTS_ALLOWED_IN_PRESENT_MODE)
    def test_present_mode_sfn_task_validation_pass(
        self,
        aws_client_no_sync_prefix,
        account_id,
        region_name,
        sfn_snapshot,
        result,
    ):
        """
        This test is not throwing validation error but rather checks that the edge case where validation passes in PRESENT mode.
        """
        template = TST.load_sfn_template(TST.BASE_SFN_START_EXECUTION_TASK_STATE)
        definition = json.dumps(template)

        target_state_machine_arn = arns.stepfunctions_state_machine_arn(
            name="TargetStateMachine", account_id=account_id, region_name=region_name
        )

        target_execution_name = "TestStartTarget"

        exec_input = json.dumps(
            {
                "stateMachineArn": target_state_machine_arn,
                "targetInput": None,
                "name": target_execution_name,
            }
        )

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        test_state_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_state_response", test_state_response)

    SFN_MALFORMED_RESULTS_NOT_ALLOWED_IN_PRESENT_MODE = [
        pytest.param(
            {
                "StartDate": True
            },  # ExecutionArn required field is not present but that won't be an error in PRESENT mode, the format of the present field will be though
            id="wrong_timestamp_type_bool",
        ),
        pytest.param(
            {
                "ExecutionArn": 1764103483
            },  # StartDate required field is not present but that won't be an error in PRESENT mode, the format of the present field will be though
            id="wrong_string_type_number",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", SFN_MALFORMED_RESULTS_NOT_ALLOWED_IN_PRESENT_MODE)
    def test_present_mode_sfn_task_validation_fail(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        account_id,
        region_name,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_SFN_START_EXECUTION_TASK_STATE)
        definition = json.dumps(template)

        target_state_machine_arn = arns.stepfunctions_state_machine_arn(
            name="TargetStateMachine", account_id=account_id, region_name=region_name
        )

        target_execution_name = "TestStartTarget"

        exec_input = json.dumps(
            {
                "stateMachineArn": target_state_machine_arn,
                "targetInput": None,
                "name": target_execution_name,
            }
        )

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    LAMBDA_VALIDATION_ERRORS = [
        pytest.param(
            {
                "StatusCode": "200"
            },  # StatusCode is not a required field but is validated because it is present
            id="wrong_integer_type_string",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", LAMBDA_VALIDATION_ERRORS)
    def test_present_mode_lambda_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": "function_name", "Payload": None})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    DYNAMODB_VALIDATION_ERRORS = [
        pytest.param(
            {"ConsumedCapacity": {"CapacityUnits": "123.45"}},
            id="wrong_float_type_string",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", DYNAMODB_VALIDATION_ERRORS)
    def test_present_mode_dynamodb_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_DYNAMODB_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "TableName": "table_name",
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
            }
        )

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    AWS_SDK_S3_VALIDATION_ERRORS = [
        pytest.param(
            {"ContentLength": "9000"},
            id="wrong_long_type_string",
        ),
        pytest.param(
            {"StorageClass": "Papyrus"},
            id="non_existent_enum_value",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", AWS_SDK_S3_VALIDATION_ERRORS)
    def test_present_mode_aws_sdk_s3_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_S3_GET_OBJECT_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Bucket": "bucket_name", "Key": "file_key"})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    AWS_SDK_KMS_VALIDATION_ERRORS = [
        pytest.param(
            {"CiphertextBlob": 123},
            id="wrong_blob_type_number",
        ),
        pytest.param(
            {"CiphertextBlob": ""},
            id="wrong_blob_length_less_than_minimum",
            marks=pytest.mark.skipif(
                condition=not is_aws_cloud(),
                reason="string value length validation is not implemented yet",
            ),
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", AWS_SDK_KMS_VALIDATION_ERRORS)
    def test_present_mode_aws_sdk_kms_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_KMS_ENCRYPT_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"KeyId": "key_id", "Plaintext": "plain_text"})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    AWS_SDK_LAMBDA_GET_FUNCTION_VALIDATION_ERRORS = [
        pytest.param(
            {"Configuration": {"MemorySize": 127}},
            id="integer_less_than_minimum_allowed",
        ),
        pytest.param(
            {"Configuration": {"MemorySize": 10241}},
            id="integer_more_than_maximum_allowed",
        ),
    ]

    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="number value range validation is not implemented yet"
    )  # TODO implement number value range validation
    @markers.aws.validated
    @pytest.mark.parametrize("result", AWS_SDK_LAMBDA_GET_FUNCTION_VALIDATION_ERRORS)
    def test_present_mode_aws_sdk_lambda_get_function_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_LAMBDA_GET_FUNCTION)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": "function_name"})

        mock = {"result": json.dumps(result), "fieldValidationMode": "PRESENT"}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)
