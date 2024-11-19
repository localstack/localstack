import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_execution
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.assign.assign_templates import AssignTemplate
from tests.aws.services.stepfunctions.templates.querylanguage.query_language_templates import (
    QueryLanguageTemplate as QLT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestMixedQueryLanguageFlow:
    @pytest.mark.parametrize(
        "template",
        [
            QLT.load_sfn_template(QLT.JSONATA_ASSIGN_JSONPATH_REF),
            QLT.load_sfn_template(QLT.JSONPATH_ASSIGN_JSONATA_REF),
        ],
        ids=["JSONATA_ASSIGN_JSONPATH_REF", "JSONPATH_ASSIGN_JSONATA_REF"],
    )
    @markers.aws.validated
    def test_variable_sampling(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        definition = json.dumps(template)
        exec_input = json.dumps({})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.parametrize(
        "template",
        [
            QLT.load_sfn_template(QLT.JSONATA_OUTPUT_TO_JSONPATH),
            QLT.load_sfn_template(QLT.JSONPATH_OUTPUT_TO_JSONATA),
        ],
        ids=["JSONATA_OUTPUT_TO_JSONPATH", "JSONPATH_OUTPUT_TO_JSONATA"],
    )
    @markers.aws.validated
    def test_output_to_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        definition = json.dumps(template)
        exec_input = json.dumps({"input_data": "test"})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @markers.aws.validated
    def test_task_dataflow_to_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"fn-data-flow-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = AssignTemplate.load_sfn_template(QLT.JSONPATH_TO_JSONATA_DATAFLOW)
        definition = json.dumps(template)
        exec_input = json.dumps({"functionName": function_arn})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.parametrize(
        "template",
        [
            QLT.load_sfn_template(QLT.TASK_LAMBDA_LEGACY_RESOURCE_JSONATA_TO_JSONPATH),
            QLT.load_sfn_template(QLT.TASK_LAMBDA_SDK_RESOURCE_JSONATA_TO_JSONPATH),
            QLT.load_sfn_template(QLT.TASK_LAMBDA_LEGACY_RESOURCE_JSONPATH_TO_JSONATA),
            QLT.load_sfn_template(QLT.TASK_LAMBDA_SDK_RESOURCE_JSONPATH_TO_JSONATA),
        ],
        ids=[
            "TASK_LAMBDA_LEGACY_RESOURCE_JSONATA_TO_JSONPATH",
            "TASK_LAMBDA_SDK_RESOURCE_JSONATA_TO_JSONPATH",
            "TASK_LAMBDA_LEGACY_RESOURCE_JSONPATH_TO_JSONATA",
            "TASK_LAMBDA_SDK_RESOURCE_JSONPATH_TO_JSONATA",
        ],
    )
    @markers.aws.validated
    def test_lambda_task_resource_data_flow(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        function_name = f"fn-data-flow-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            QLT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )
