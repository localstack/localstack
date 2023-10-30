import json

import pytest

from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.templates.timeouts.timeout_templates import (
    TimeoutTemplates as TT,
)
from tests.aws.services.stepfunctions.utils import create_and_record_execution, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestTaskServiceLambda:
    @markers.aws.validated
    def test_raise_exception(
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
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_UNKNOWN)
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
    def test_raise_exception_catch(
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
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_RELEVANT)
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
    def test_no_such_function(
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
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_UNKNOWN)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": f"no_such_{function_name}", "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_no_such_function_catch(
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
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime="python3.9",
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = EHT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_RELEVANT)
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": f"no_such_{function_name}", "Payload": None})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_invoke_timeout(
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

        template = TT.load_sfn_template(EHT.AWS_SERVICE_LAMBDA_INVOKE_CATCH_TIMEOUT)
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
