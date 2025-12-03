import json
from datetime import datetime

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import long_uid, md5, short_uid
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestStateMockScenarios:
    @markers.aws.validated
    def test_base_lambda_service_task_mock_is_not_json_string(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        mock = {
            "result": "not JSON string",
            "fieldValidationMode": "NONE",  # the result must be a valid JSON string even if field validation mode is NONE
        }

        with pytest.raises(aws_client.stepfunctions.exceptions.ValidationException) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.INFO,
                mock=mock,
            )
        sfn_snapshot.match("validation-exception", e.value.response)

    @markers.aws.validated
    def test_base_lambda_service_task_mock_success(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        result = {
            # Lambda API spec requires response payload to be a string.
            # However, when not mocked, optimized lambda task output is a JSON.
            # TODO Clarify whether such transformation is supposed to happen in TestState call as well or there is a caveat.
            "Payload": "function output",
            "SdkHttpMetadata": {"HttpStatusCode": 200},
        }
        mock = {"result": json.dumps(result)}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    DYNAMODB_TEMPLATES = [
        pytest.param(TST.BASE_DYNAMODB_SERVICE_TASK_STATE, id="base"),
        pytest.param(TST.IO_DYNAMODB_SERVICE_TASK_STATE, id="io"),
        pytest.param(TST.IO_OUTPUT_PATH_DYNAMODB_SERVICE_TASK_STATE, id="io_output_path"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("template_path", DYNAMODB_TEMPLATES)
    def test_io_dynamodb_service_task_mock_success(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        template_path,
    ):
        table_name = f"sfn_test_table_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(table_name, "<table_name>"))

        template = TST.load_sfn_template(template_path)
        definition = json.dumps(template)
        exec_input = json.dumps(
            {
                "TableName": table_name,
                "Item": {"data": {"S": "HelloWorld"}, "id": {"S": "id1"}},
            }
        )
        result = {"SdkHttpMetadata": {"HttpStatusCode": 200}}
        mock = {"result": json.dumps(result)}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    def test_put_events_mock_success(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
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

        result = {"Entries": [{"EventId": long_uid()}]}
        mock = {"result": json.dumps(result)}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    def test_send_sqs_message_success(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TST.load_sfn_template(TST.BASE_SQS_SEND_MESSAGE_TASK_STATE)
        definition = json.dumps(template)

        message_body = "message_body"
        md5_of_message_body = md5(message_body)
        sfn_snapshot.add_transformer(RegexTransformer(md5_of_message_body, "<md5_of_message_body>"))

        exec_input = json.dumps({"QueueUrl": "queue_url", "MessageBody": message_body})
        result = {"MD5OfMessageBody": md5_of_message_body, "MessageId": long_uid()}
        mock = {"result": json.dumps(result)}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    def test_sfn_start_execution_success(
        self,
        aws_client_no_sync_prefix,
        account_id,
        region_name,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..output..StartDate",
                replacement="start-date",
                replace_reference=False,
            )
        )

        template = TST.load_sfn_template(TST.BASE_SFN_START_EXECUTION_TASK_STATE)
        definition = json.dumps(template)

        target_state_machine_arn = arns.stepfunctions_state_machine_arn(
            name="TargetStateMachine", account_id=account_id, region_name=region_name
        )

        target_execution_name = "TestStartTarget"
        target_execution_arn = arns.stepfunctions_standard_execution_arn(
            target_state_machine_arn, target_execution_name
        )

        exec_input = json.dumps(
            {
                "stateMachineArn": target_state_machine_arn,
                "targetInput": None,
                "name": target_execution_name,
            }
        )

        result = {"ExecutionArn": target_execution_arn, "StartDate": datetime.now().isoformat()}
        mock = {"result": json.dumps(result)}

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)
