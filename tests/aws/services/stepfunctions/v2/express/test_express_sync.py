import json

import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_express_sync_execution
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.base.base_templates import BaseTemplate
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate,
)
from tests.aws.services.stepfunctions.templates.scenarios.scenarios_templates import (
    ScenariosTemplate,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..loggingConfiguration",
        "$..tracingConfiguration",
        "$..billingDetails",
        "$..output.Cause",
    ]
)
class TestExpressSync:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "template",
        [BaseTemplate.BASE_PASS_RESULT, BaseTemplate.BASE_RAISE_FAILURE],
        ids=["BASE_PASS_RESULT", "BASE_RAISE_FAILURE"],
    )
    def test_base(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        sqs_create_queue,
        sfn_snapshot,
        stepfunctions_client_sync_executions,
        template,
    ):
        definition = json.dumps(BaseTemplate.load_sfn_template(template))
        exec_input = json.dumps({})
        create_and_record_express_sync_execution(
            stepfunctions_client_sync_executions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.snapshot.skip_snapshot_verify(paths=["$..RedriveCount"])
    @markers.aws.validated
    def test_query_runtime_memory(
        self,
        create_iam_role_for_sfn,
        create_state_machine,
        stepfunctions_client_sync_executions,
        sfn_snapshot,
    ):
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..StartTime", replacement="start-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..execution_starttime", replacement="start-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..EnteredTime", replacement="entered-time", replace_reference=False
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                jsonpath="$..state_enteredtime", replacement="entered-time", replace_reference=False
            )
        )

        template = BaseTemplate.load_sfn_template(BaseTemplate.QUERY_CONTEXT_OBJECT_VALUES)
        definition = json.dumps(template)

        exec_input = json.dumps({"message": "HelloWorld!"})
        create_and_record_express_sync_execution(
            stepfunctions_client_sync_executions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_catch(
        self,
        stepfunctions_client_sync_executions,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ErrorHandlingTemplate.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))

        template = ErrorHandlingTemplate.load_sfn_template(
            ErrorHandlingTemplate.AWS_SERVICE_LAMBDA_INVOKE_CATCH_ALL
        )
        definition = json.dumps(template)

        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})
        create_and_record_express_sync_execution(
            stepfunctions_client_sync_executions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )

    @markers.aws.validated
    def test_retry(
        self,
        aws_client,
        stepfunctions_client_sync_executions,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ErrorHandlingTemplate.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "lambda_function_name"))
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        template = ScenariosTemplate.load_sfn_template(
            ScenariosTemplate.LAMBDA_INVOKE_WITH_RETRY_BASE_EXTENDED_INPUT
        )
        template["States"]["InvokeLambdaWithRetry"]["Resource"] = function_arn
        definition = json.dumps(template)

        exec_input = json.dumps({})
        create_and_record_express_sync_execution(
            stepfunctions_client_sync_executions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
