import json

import pytest
from localstack_snapshot.snapshots import JsonpathTransformer, RegexTransformer

from localstack.aws.api.lambda_ import LogType
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        # TODO: add support for Sdk Http metadata.
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestTaskServiceLambda:
    @markers.aws.validated
    def test_invoke(
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

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE)
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
    def test_invoke_bytes_payload(
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
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"FunctionName": function_name, "Payload": json.dumps("'{'Hello':'World'}'")}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    # AWS's stepfuctions documentation seems to incorrectly classify LogType parameters as unsupported.
    @markers.aws.validated
    def test_invoke_unsupported_param(
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
        sfn_snapshot.add_transformer(
            JsonpathTransformer("$..LogResult", "LogResult", replace_reference=True)
        )

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE_LOG_TYPE)
        definition = json.dumps(template)

        exec_input = json.dumps(
            {"FunctionName": function_name, "Payload": None, "LogType": LogType.Tail}
        )
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @pytest.mark.parametrize(
        "json_value",
        [
            "HelloWorld",
            0.0,
            0,
            -0,
            True,
            {},
            [],
        ],
    )
    @markers.aws.validated
    def test_invoke_json_values(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
        json_value,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))
        sfn_snapshot.add_transformer(
            JsonpathTransformer("$..LogResult", "LogResult", replace_reference=True)
        )

        template = ST.load_sfn_template(ST.LAMBDA_INVOKE)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": json.dumps(json_value)})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @pytest.mark.skipif(
        condition=not is_aws_cloud(),
        reason="Add support for Invalid State Machine Definition errors",
    )
    @markers.aws.needs_fixing
    def test_list_functions(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = ST.load_sfn_template(ST.LAMBDA_LIST_FUNCTIONS)
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
