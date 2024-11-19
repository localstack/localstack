import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.outputdecl.output_templates import OutputTemplates
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as SerT,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..RedriveCount",
        "$..SdkResponseMetadata",
    ]
)
class TestArgumentsBase:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            OutputTemplates.BASE_EMPTY,
            OutputTemplates.BASE_LITERALS,
            OutputTemplates.BASE_EXPR,
            OutputTemplates.BASE_DIRECT_EXPR,
        ],
        ids=[
            "BASE_EMPTY",
            "BASE_LITERALS",
            "BASE_EXPR",
            "BASE_DIRECT_EXPR",
        ],
    )
    def test_base_cases(
        self,
        sfn_snapshot,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        template_path,
    ):
        template = OutputTemplates.load_sfn_template(template_path)
        definition = json.dumps(template)
        exec_input = json.dumps({"input_value": "string literal", "input_values": [1, 2, 3]})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            OutputTemplates.BASE_LAMBDA,
        ],
        ids=[
            "BASE_LAMBDA",
        ],
    )
    def test_base_lambda(
        self,
        sfn_snapshot,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        template_path,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=SerT.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]
        template = OutputTemplates.load_sfn_template(template_path)
        template["States"]["State0"]["Resource"] = function_arn
        definition = json.dumps(template)
        exec_input = json.dumps({"input_value": "string literal", "input_values": [1, 2, 3]})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "template_path",
        [
            OutputTemplates.BASE_TASK_LAMBDA,
        ],
        ids=[
            "BASE_TASK_LAMBDA",
        ],
    )
    def test_base_task_lambda(
        self,
        sfn_snapshot,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        template_path,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=SerT.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))

        template = OutputTemplates.load_sfn_template(template_path)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {
                "FunctionName": function_name,
                "Payload": {"input_value": "string literal", "input_values": [1, 2, 3]},
            }
        )
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize(
        "output_value",
        [
            None,
            0,
            0.1,
            True,
            "string literal",
            "{% $states.input %}",
            [],
            [
                None,
                0,
                0.1,
                True,
                "string",
                [],
                "$nosuchvar",
                "$.no.such.path",
                "{% $states.input %}",
                {"key": "{% true %}"},
            ],
        ],
        ids=[
            "NULL",
            "INT",
            "FLOAT",
            "BOOL",
            "STR_LIT",
            "JSONATA_EXPR",
            "LIST_EMPY",
            "LIST_RICH",
        ],
    )
    def test_base_output_any_non_dict(
        self,
        sfn_snapshot,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        output_value,
    ):
        template = OutputTemplates.load_sfn_template(OutputTemplates.BASE_OUTPUT_ANY)
        template["States"]["State0"]["Output"] = output_value
        definition = json.dumps(template)

        exec_input = json.dumps({"input_value": "stringliteral"})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )
