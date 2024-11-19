import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import (
    create_and_record_execution,
)
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.evaluatejsonata.evaluate_jsonata_templates import (
    EvaluateJsonataTemplate as EJT,
)
from tests.aws.services.stepfunctions.templates.querylanguage.query_language_templates import (
    QueryLanguageTemplate as QLT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..redriveCount",
        "$..redriveStatus",
        "$..RedriveCount",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestBaseEvaluateJsonata:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "expression_dict",
        [
            {"TimeoutSeconds": EJT.JSONATA_NUMBER_EXPRESSION},
            {"HeartbeatSeconds": EJT.JSONATA_NUMBER_EXPRESSION},
        ],
        ids=[
            "TIMEOUT_SECONDS",
            "HEARTBEAT_SECONDS",
        ],
    )
    def test_base_task(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        expression_dict,
    ):
        function_name = f"fn-eval-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = EJT.load_sfn_template(EJT.BASE_TASK)
        template["States"]["Start"].update(expression_dict)
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

    @markers.aws.validated
    @pytest.mark.parametrize(
        "expression_dict",
        [
            pytest.param(
                {"Items": EJT.JSONATA_ARRAY_ELEMENT_EXPRESSION},
                marks=pytest.mark.skipif(
                    condition=not is_aws_cloud(),
                    reason="Single-quote esacped JSONata expressions are not yet supported",
                ),
            ),
            {"Items": EJT.JSONATA_ARRAY_ELEMENT_EXPRESSION_DOUBLE_QUOTES},
            {"MaxConcurrency": EJT.JSONATA_NUMBER_EXPRESSION},
            {"ToleratedFailurePercentage": EJT.JSONATA_NUMBER_EXPRESSION},
            {"ToleratedFailureCount": EJT.JSONATA_NUMBER_EXPRESSION},
        ],
        ids=[
            "ITEMS",
            "ITEMS_DOUBLE_QUOTES",
            "MAX_CONCURRENCY",
            "TOLERATED_FAILURE_PERCENTAGE",
            "TOLERATED_FAILURE_COUNT",
        ],
    )
    def test_base_map(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        expression_dict,
    ):
        template = EJT.load_sfn_template(EJT.BASE_MAP)
        template["States"]["Start"].update(expression_dict)
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

    @markers.aws.validated
    @pytest.mark.parametrize(
        "field,input_value",
        [
            pytest.param("TimeoutSeconds", 1, id="TIMEOUT_SECONDS"),
            pytest.param("HeartbeatSeconds", 1, id="HEARTBEAT_SECONDS"),
        ],
    )
    def test_base_task_from_input(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        field,
        input_value,
    ):
        function_name = f"fn-eval-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = EJT.load_sfn_template(EJT.BASE_TASK)
        template["States"]["Start"][field] = EJT.JSONATA_STATE_INPUT_EXPRESSION
        definition = json.dumps(template)
        definition = definition.replace(
            QLT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )

        exec_input = json.dumps({"input_value": input_value})
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
        "field,input_value",
        [
            pytest.param("Items", [1, 2, 3], id="ITEMS"),
            pytest.param("MaxConcurrency", 1, id="MAX_CONCURRENCY"),
            pytest.param("ToleratedFailurePercentage", 100, id="TOLERATED_FAILURE_PERCENTAGE"),
            pytest.param("ToleratedFailureCount", 1, id="TOLERATED_FAILURE_COUNT"),
        ],
        ids=[
            "ITEMS",
            "MAX_CONCURRENCY",
            "TOLERATED_FAILURE_PERCENTAGE",
            "TOLERATED_FAILURE_COUNT",
        ],
    )
    def test_base_map_from_input(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        create_lambda_function,
        field,
        input_value,
    ):
        function_name = f"fn-eval-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = EJT.load_sfn_template(EJT.BASE_MAP)
        template["States"]["Start"][field] = EJT.JSONATA_STATE_INPUT_EXPRESSION
        definition = json.dumps(template)
        definition = definition.replace(
            QLT.LAMBDA_FUNCTION_ARN_LITERAL_PLACEHOLDER,
            function_arn,
        )

        exec_input = json.dumps({"input_value": input_value})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )
