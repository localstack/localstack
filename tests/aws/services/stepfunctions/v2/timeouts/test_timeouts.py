import json

import pytest
from localstack_snapshot.snapshots import RegexTransformer

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.templates.timeouts.timeout_templates import (
    TimeoutTemplates as TT,
)
from tests.aws.services.stepfunctions.utils import (
    await_execution_terminated,
    create_and_record_execution,
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestTimeouts:
    @markers.aws.validated
    def test_global_timeout(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        snf_role_arn = create_iam_role_for_sfn()

        template = TT.load_sfn_template(BaseTemplate.BASE_WAIT_1_MIN)
        template["TimeoutSeconds"] = 1
        definition = json.dumps(template)

        creation_resp = create_state_machine(
            name=f"test_global_timeout-{short_uid()}", definition=definition, roleArn=snf_role_arn
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        execution_name = f"exec_of-test_global_timeout-{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(execution_name, "<execution-name>"))

        exec_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, name=execution_name
        )
        execution_arn = exec_resp["executionArn"]

        await_execution_terminated(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        describe_execution = aws_client.stepfunctions.describe_execution(executionArn=execution_arn)
        sfn_snapshot.match("describe_execution", describe_execution)

    @markers.aws.validated
    def test_fixed_timeout_service_lambda(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_1_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TT.LAMBDA_WAIT_60_SECONDS,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_1_name>"))

        template = TT.load_sfn_template(TT.SERVICE_LAMBDA_WAIT_WITH_TIMEOUT_SECONDS)
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
    def test_fixed_timeout_service_lambda_with_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_1_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TT.LAMBDA_WAIT_60_SECONDS,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_1_name>"))

        template = TT.load_sfn_template(
            TT.SERVICE_LAMBDA_MAP_FUNCTION_INVOKE_WITH_TIMEOUT_SECONDS_PATH
        )
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"TimeoutSecondsValue": 1, "FunctionName": function_name, "Payload": None}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_fixed_timeout_lambda(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_1_func_{short_uid()}"
        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TT.LAMBDA_WAIT_60_SECONDS,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_1_name>"))
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]

        template = TT.load_sfn_template(TT.LAMBDA_WAIT_WITH_TIMEOUT_SECONDS)
        template["States"]["Start"]["Resource"] = lambda_arn
        definition = json.dumps(template)

        exec_input = json.dumps({"Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="Add support for State Map event history first."
    )
    @markers.aws.needs_fixing
    def test_service_lambda_map_timeout(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_1_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TT.LAMBDA_WAIT_60_SECONDS,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_1_name>"))

        template = TT.load_sfn_template(TT.SERVICE_LAMBDA_MAP_FUNCTION_INVOKE_WITH_TIMEOUT_SECONDS)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "Inputs": [
                    {"FunctionName": function_name, "Payload": None},
                    {"FunctionName": function_name, "Payload": None},
                    {"FunctionName": function_name, "Payload": None},
                    {"FunctionName": function_name, "Payload": None},
                ]
            }
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
