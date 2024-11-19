import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    SfnNoneRecursiveParallelTransformer,
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.templates.statevariables.state_variables_template import (
    StateVariablesTemplate as SVT,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestStateVariablesTemplate:
    @pytest.mark.parametrize(
        "template",
        [
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_OUTPUT),
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_OUTPUT_TO_JSONPATH),
        ],
        ids=[
            "TASK_CATCH_ERROR_OUTPUT",
            "TASK_CATCH_ERROR_OUTPUT_TO_JSONPATH",
        ],
    )
    @markers.aws.validated
    def test_task_catch_error_output(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        function_name = f"fn-exception-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            SVT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({"inputData": "dummy"})
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
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_VARIABLE_SAMPLING),
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_VARIABLE_SAMPLING_TO_JSONPATH),
        ],
        ids=[
            "TASK_CATCH_ERROR_VARIABLE_SAMPLING",
            "TASK_CATCH_ERROR_VARIABLE_SAMPLING_TO_JSONPATH",
        ],
    )
    @markers.aws.validated
    def test_catch_error_variable_sampling(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        function_name = f"fn-exception-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            SVT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({"inputData": "dummy"})
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
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_OUTPUT_WITH_RETRY),
            SVT.load_sfn_template(SVT.TASK_CATCH_ERROR_OUTPUT_WITH_RETRY_TO_JSONPATH),
        ],
        ids=[
            "TASK_CATCH_ERROR_OUTPUT_WITH_RETRY",
            "TASK_CATCH_ERROR_OUTPUT_WITH_RETRY_TO_JSONPATH",
        ],
    )
    @markers.aws.validated
    def test_task_catch_error_with_retry(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        function_name = f"fn-exception-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            SVT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({"inputData": "dummy"})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.skip(reason="Items declarations is currently unsupported.")
    @pytest.mark.parametrize(
        "template",
        [
            SVT.load_sfn_template(SVT.MAP_CATCH_ERROR_OUTPUT),
            SVT.load_sfn_template(SVT.MAP_CATCH_ERROR_OUTPUT_WITH_RETRY),
            SVT.load_sfn_template(SVT.MAP_CATCH_ERROR_VARIABLE_SAMPLING),
        ],
        ids=[
            "MAP_CATCH_ERROR_OUTPUT",
            "MAP_CATCH_ERROR_OUTPUT_WITH_RETRY",
            "MAP_CATCH_ERROR_VARIABLE_SAMPLING",
        ],
    )
    @markers.aws.validated
    def test_map_catch_error(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        function_name = f"fn-exception-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            SVT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({"items": [1, 2, 3]})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.skip(reason="Review error workflow handling for parallel states.")
    @pytest.mark.parametrize(
        "template",
        [
            SVT.load_sfn_template(SVT.PARALLEL_CATCH_ERROR_OUTPUT),
            SVT.load_sfn_template(SVT.PARALLEL_CATCH_ERROR_VARIABLE_SAMPLING),
            SVT.load_sfn_template(SVT.PARALLEL_CATCH_ERROR_OUTPUT_WITH_RETRY),
        ],
        ids=[
            "PARALLEL_CATCH_ERROR_OUTPUT",
            "PARALLEL_CATCH_ERROR_VARIABLE_SAMPLING",
            "PARALLEL_CATCH_ERROR_OUTPUT_WITH_RETRY",
        ],
    )
    @markers.aws.validated
    def test_parallel_catch_error(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        template,
    ):
        sfn_snapshot.add_transformer(SfnNoneRecursiveParallelTransformer())
        function_name = f"fn-exception-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        definition = json.dumps(template)
        definition = definition.replace(
            SVT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )
        exec_input = json.dumps({"inputData": "dummy"})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )
