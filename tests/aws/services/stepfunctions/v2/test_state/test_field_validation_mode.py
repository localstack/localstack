import json

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestFieldValidationMode:
    """

    TODO test cases and edge cases found out in the wild that are good candidates for tests
    - lambda response payload is not a string but a JSON - results in a validation error against the API spec
    - somehow in SQS SendMessage response the following mock {"MD5OfMessageBody": {"unexpected": ["object"]}} while the API spec requires {"MD5OfMessageBody": "string"}.
        At the same time, MessageId is validated to be a string. Both fields are in the API spec and both are strings there.
    """

    EVENTBRIDGE_VALIDATION_PASS_FIELDS_NOT_IN_SPEC = [
        pytest.param({"random": "json"}, id="field_not_part_of_api_spec"),
        pytest.param({}, id="empty_json"),
        # pytest.param("Hello World", id="simple_string"), TODO validate these general failure modes in a validation parity test
        # pytest.param(42, id="simple_number"),
        # pytest.param(["a", "b", "c"], id="simple_list"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", EVENTBRIDGE_VALIDATION_PASS_FIELDS_NOT_IN_SPEC)
    def test_strict_mode_mock_result_field_not_in_api_spec(
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

        mock = {"result": json.dumps(result)}

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
    def test_strict_mode_eventbridge_task(
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

        mock = {"result": json.dumps(result)}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    SFN_VALIDATION_ERRORS = [
        pytest.param(
            {},
            id="missing_required_fields",
        ),
        pytest.param(
            {"executionArn": "stringValueExecutionArn", "startDate": "stringValueStartDate"},
            id="field_name_not_in_sfn_case",
        ),
        pytest.param(
            {"ExecutionArn": "stringValueExecutionArn", "StartDate": True},
            id="wrong_timestamp_type_bool",
        ),
        pytest.param(
            {"ExecutionArn": "stringValueExecutionArn", "StartDate": 1764103483},
            id="wrong_timestamp_type_number",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", SFN_VALIDATION_ERRORS)
    def test_strict_mode_sfn_task(
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

        mock = {"result": json.dumps(result)}

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
            {"StatusCode": "200"},
            id="wrong_integer_type_string",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", LAMBDA_VALIDATION_ERRORS)
    def test_strict_mode_lambda_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": "function_name", "Payload": None})

        mock = {"result": json.dumps(result)}

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
    def test_strict_mode_dynamodb_task(
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

        mock = {"result": json.dumps(result)}

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
    def test_strict_mode_aws_sdk_s3_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_S3_GET_OBJECT_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"Bucket": "bucket_name", "Key": "file_key"})

        mock = {"result": json.dumps(result)}

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
            ),  # TODO implement value length validation
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", AWS_SDK_KMS_VALIDATION_ERRORS)
    def test_strict_mode_aws_sdk_kms_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_KMS_ENCRYPT_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"KeyId": "key_id", "Plaintext": "plain_text"})

        mock = {"result": json.dumps(result)}

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
    def test_strict_mode_aws_sdk_lambda_get_function_task(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_AWS_SDK_LAMBDA_GET_FUNCTION)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": "function_name"})

        mock = {"result": json.dumps(result)}

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)
