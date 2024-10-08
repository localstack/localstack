import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.context_object.context_object_templates import (
    ContextObjectTemplates,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..RedriveCount",
        "$..RedriveStatus",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestSnfBase:
    @markers.aws.validated
    @pytest.mark.parametrize("context_object_literal", ["$$", "$$.Execution.Input"])
    def test_input_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        context_object_literal,
    ):
        template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_INPUT_PATH
        )
        definition = json.dumps(template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, context_object_literal
        )
        exec_input = json.dumps({"input-value": 0})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    @pytest.mark.parametrize("context_object_literal", ["$$", "$$.Execution.Input"])
    def test_output_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        context_object_literal,
    ):
        template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_OUTPUT_PATH
        )
        definition = json.dumps(template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, context_object_literal
        )
        exec_input = json.dumps({"input-value": 0})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_result_selector(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_RESULT_PATH
        )
        definition = json.dumps(template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER, "$$.Execution.Input"
        )

        exec_input = json.dumps({"FunctionName": function_name, "Payload": {"input-value": 0}})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_variable(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_VARIABLE
        )
        definition = json.dumps(template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER,
            "$$.Execution.Input.input-value",
        )
        exec_input = json.dumps({"input-value": 0})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_items_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ContextObjectTemplates.load_sfn_template(
            ContextObjectTemplates.CONTEXT_OBJECT_ITEMS_PATH
        )
        definition = json.dumps(template)
        definition = definition.replace(
            ContextObjectTemplates.CONTEXT_OBJECT_LITERAL_PLACEHOLDER,
            "$$.Execution.Input.input-values",
        )
        exec_input = json.dumps({"input-values": ["item-0"]})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
