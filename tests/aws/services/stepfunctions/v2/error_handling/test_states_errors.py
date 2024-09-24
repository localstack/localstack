import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
    ]
)
class TestStatesErrors:
    @markers.aws.validated
    def test_service_task_lambada_data_limit_exceeded_on_large_utf8_response(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        """
        This test checks the 'DataLimitExceeded' error when a service lambda task returns a large UTF-8 response.
        It creates a lambda function with a large output string, then creates and records an execution of a
        state machine that invokes the lambda function. The test verifies that the state machine correctly
        raises the 'DataLimitExceeded' error.
        """
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_LARGE_OUTPUT_STRING,
            runtime="python3.12",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_DATA_LIMIT_EXCEEDED)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_service_task_lambada_catch_state_all_data_limit_exceeded_on_large_utf8_response(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        """
        This test checks the 'DataLimitExceeded' error when a service lambda task returns a large UTF-8 response.
        It creates a lambda function with a large output string, then creates and records an execution of a
        state machine that invokes the lambda function. The test verifies that the state machine correctly
        raises and handles the 'DataLimitExceeded' error.
        """

        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_LARGE_OUTPUT_STRING,
            runtime="python3.12",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_ALL)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_task_lambda_data_limit_exceeded_on_large_utf8_response(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        """
        This test checks the 'DataLimitExceeded' error when a legacy lambda task returns a large UTF-8 response.
        This is different from a service lambda task as the state machine invokes the lambda function directly using
        its arn, rather than passing the parameters results to the states invoke call.
        It creates a lambda function with a large output string, then creates and records an execution of a
        state machine that invokes the lambda function. The test verifies that the state machine correctly
        raises the 'DataLimitExceeded' error.
        """

        function_name = f"lambda_func_{short_uid()}"
        create_lambda_response = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_LARGE_OUTPUT_STRING,
            runtime="python3.12",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_DATA_LIMIT_EXCEEDED)
        template["States"]["InvokeLambda"]["Resource"] = function_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_task_lambda_catch_state_all_data_limit_exceeded_on_large_utf8_response(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        """
        This test checks the 'DataLimitExceeded' error when a legacy lambda task returns a large UTF-8 response.
        This is different from a service lambda task as the state machine invokes the lambda function directly using
        its arn, rather than passing the parameters results to the states invoke call.
        It creates a lambda function with a large output string, then creates and records an execution of a
        state machine that invokes the lambda function. The test verifies that the state machine correctly
        raises and handles the 'DataLimitExceeded' error.
        """

        function_name = f"lambda_func_{short_uid()}"
        create_lambda_response = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_LARGE_OUTPUT_STRING,
            runtime="python3.12",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        function_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_ALL)
        template["States"]["InvokeLambda"]["Resource"] = function_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_start_large_input(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        """
        This test checks the 'DataLimitExceeded' error from a non-task state.
        In this case, it defines a 'Pass' state with a result that exceeds the given quota.
        The test verifies that the state machine correctly raises the 'DataLimitExceeded' error.
        """

        two_bytes_utf8_char = "a"
        template = {
            "StartAt": "State_1",
            "States": {
                "State_1": {
                    "Type": "Pass",
                    "Result": {
                        "Arg1": two_bytes_utf8_char
                        * (257 * 1024 // len(two_bytes_utf8_char.encode("utf-8")))
                    },
                    "End": True,
                }
            },
        }
        definition = json.dumps(template)

        exec_input = json.dumps(dict())
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
