import json

import pytest
from localstack_snapshot.snapshots.transformer import GenericTransformer, RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_execution
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.assign.assign_templates import (
    AssignTemplate as AT,
)
from tests.aws.services.stepfunctions.templates.errorhandling.error_handling_templates import (
    ErrorHandlingTemplate as EHT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..SdkHttpMetadata",
        "$..RedriveCount",
        "$..SdkResponseMetadata",
    ]
)
class TestAssignReferenceVariables:
    @pytest.mark.parametrize(
        "template_path",
        [
            AT.BASE_REFERENCE_IN_PARAMETERS,
            AT.BASE_REFERENCE_IN_CHOICE,
            AT.BASE_REFERENCE_IN_WAIT,
            AT.BASE_REFERENCE_IN_ITERATOR_OUTER_SCOPE,
            AT.BASE_REFERENCE_IN_INPUTPATH,
            AT.BASE_REFERENCE_IN_OUTPUTPATH,
            AT.BASE_REFERENCE_IN_INTRINSIC_FUNCTION,
            AT.BASE_REFERENCE_IN_FAIL,
        ],
        ids=[
            "BASE_REFERENCE_IN_PARAMETERS",
            "BASE_REFERENCE_IN_CHOICE",
            "BASE_REFERENCE_IN_WAIT",
            "BASE_REFERENCE_IN_ITERATOR_OUTER_SCOPE",
            "BASE_REFERENCE_IN_INPUTPATH",
            "BASE_REFERENCE_IN_OUTPUTPATH",
            "BASE_REFERENCE_IN_INTRINSIC_FUNCTION",
            "BASE_REFERENCE_IN_FAIL",
        ],
    )
    @markers.aws.validated
    def test_reference_assign(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template_path,
    ):
        template = AT.load_sfn_template(template_path)
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

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..events..evaluationFailedEventDetails.cause",
            "$..events..evaluationFailedEventDetails.location",
            "$..events..executionFailedEventDetails.cause",
            "$..events..previousEventId",
        ]
    )
    @pytest.mark.parametrize(
        "template",
        [
            AT.load_sfn_template(AT.BASE_UNDEFINED_OUTPUT),
            AT.load_sfn_template(AT.BASE_UNDEFINED_OUTPUT_FIELD),
            AT.load_sfn_template(AT.BASE_UNDEFINED_OUTPUT_MULTIPLE_STATES),
            AT.load_sfn_template(AT.BASE_UNDEFINED_ASSIGN),
            pytest.param(
                AT.load_sfn_template(AT.BASE_UNDEFINED_ARGUMENTS),
                marks=pytest.mark.skipif(
                    condition=not is_aws_cloud(), reason="Not reached full parity yet."
                ),
            ),
            pytest.param(
                AT.load_sfn_template(AT.BASE_UNDEFINED_ARGUMENTS_FIELD),
                marks=pytest.mark.skipif(
                    condition=not is_aws_cloud(), reason="Not reached full parity yet."
                ),
            ),
        ],
        ids=[
            "BASE_UNDEFINED_OUTPUT",
            "BASE_UNDEFINED_OUTPUT_FIELD",
            "BASE_UNDEFINED_OUTPUT_MULTIPLE_STATES",
            "BASE_UNDEFINED_ASSIGN",
            "BASE_UNDEFINED_ARGUMENTS",
            "BASE_UNDEFINED_ARGUMENTS_FIELD",
        ],
    )
    @markers.aws.validated
    def test_undefined_reference(
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
        "template_path",
        [
            AT.BASE_ASSIGN_FROM_PARAMETERS,
            AT.BASE_ASSIGN_FROM_RESULT,
            AT.BASE_ASSIGN_FROM_INTRINSIC_FUNCTION,
        ],
        ids=[
            "BASE_ASSIGN_FROM_PARAMETERS",
            "BASE_ASSIGN_FROM_RESULT",
            "BASE_ASSIGN_FROM_INTRINSIC_FUNCTION",
        ],
    )
    @markers.aws.validated
    def test_assign_from_value(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template_path,
    ):
        template = AT.load_sfn_template(template_path)
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

    @pytest.mark.skip(reason="Flaky when run in test suite")
    @pytest.mark.parametrize(
        "template_path",
        [
            AT.BASE_EVALUATION_ORDER_PASS_STATE,
        ],
        ids=[
            "BASE_EVALUATION_ORDER_PASS_STATE",
        ],
    )
    @markers.aws.validated
    def test_state_assign_evaluation_order(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template_path,
    ):
        template = AT.load_sfn_template(template_path)
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

    @pytest.mark.parametrize("input_value", ["42", "0"], ids=["CORRECT", "INCORRECT"])
    @markers.aws.validated
    def test_assign_in_choice_state(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, input_value
    ):
        template = AT.load_sfn_template(AT.BASE_ASSIGN_IN_CHOICE)
        definition = json.dumps(template)
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
    def test_assign_in_wait_state(
        self, aws_client, create_iam_role_for_sfn, create_state_machine, sfn_snapshot
    ):
        template = AT.load_sfn_template(AT.BASE_ASSIGN_IN_WAIT)
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
    def test_assign_in_catch_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_lambda_function,
        create_state_machine,
        sfn_snapshot,
    ):
        function_name = f"fn-timeout-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=EHT.LAMBDA_FUNC_RAISE_EXCEPTION,
            runtime=Runtime.python3_12,
        )
        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = AT.load_sfn_template(AT.BASE_ASSIGN_IN_CATCH)
        definition = json.dumps(template)
        exec_input = json.dumps({"input_value": function_arn})
        create_and_record_execution(
            stepfunctions_client=aws_client.stepfunctions,
            create_iam_role_for_sfn=create_iam_role_for_sfn,
            create_state_machine=create_state_machine,
            sfn_snapshot=sfn_snapshot,
            definition=definition,
            execution_input=exec_input,
        )

    @pytest.mark.parametrize(
        "template_path",
        [
            # FIXME: BASE_REFERENCE_IN_LAMBDA_TASK_FIELDS provides invalid credentials to lambda::invoke
            # AT.BASE_REFERENCE_IN_LAMBDA_TASK_FIELDS,
            AT.BASE_ASSIGN_FROM_LAMBDA_TASK_RESULT,
        ],
        ids=[
            "BASE_ASSIGN_FROM_LAMBDA_TASK_RESULT",
        ],
    )
    @markers.aws.validated
    def test_variables_in_lambda_task(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        account_id,
        sfn_snapshot,
        template_path,
    ):
        function_name = f"fn-ref-var-{short_uid()}"
        create_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime=Runtime.python3_12,
        )

        function_arn = create_res["CreateFunctionResponse"]["FunctionArn"]

        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda-function-name>"))

        template = AT.load_sfn_template(template_path)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_arn, "AccountID": account_id})
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
            AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_INTRINSIC_FUNCTION),
            AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_ITEMS_PATH),
            AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_MAX_CONCURRENCY_PATH),
            pytest.param(
                AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_TOLERATED_FAILURE_PATH),
                marks=pytest.mark.skip_snapshot_verify(paths=["$..events[8].previousEventId"]),
            ),
            pytest.param(
                AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_ITEM_SELECTOR),
                marks=pytest.mark.skip_snapshot_verify(paths=["$..events[8].previousEventId"]),
            ),
        ],
        ids=[
            "MAP_STATE_REFERENCE_IN_INTRINSIC_FUNCTION",
            "MAP_STATE_REFERENCE_IN_ITEMS_PATH",
            "MAP_STATE_REFERENCE_IN_MAX_CONCURRENCY_PATH",
            "MAP_STATE_REFERENCE_IN_TOLERATED_FAILURE_PATH",
            "MAP_STATE_REFERENCE_IN_ITEM_SELECTOR",
        ],
    )
    @markers.aws.validated
    def test_reference_in_map_state(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        def _convert_output_to_json(snapshot_content: dict, *args) -> dict:
            """Recurse through all elements in the snapshot and convert the json-string `output` to a dict"""
            for _, v in snapshot_content.items():
                if isinstance(v, dict):
                    if "output" in v:
                        try:
                            if isinstance(v["output"], str):
                                v["output"] = json.loads(v["output"])
                                return
                        except json.JSONDecodeError:
                            pass
                    v = _convert_output_to_json(v)
                elif isinstance(v, list):
                    v = [
                        _convert_output_to_json(item) if isinstance(item, dict) else item
                        for item in v
                    ]
            return snapshot_content

        sfn_snapshot.add_transformer(GenericTransformer(_convert_output_to_json))

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

    @pytest.mark.parametrize(
        "template",
        [
            pytest.param(
                AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_MAX_ITEMS_PATH),
                marks=pytest.mark.skip_snapshot_verify(paths=["$..events[8].previousEventId"]),
            ),
            # TODO: Add JSONata support for ItemBatcher's MaxItemsPerBatch and MaxInputBytesPerBatch fields
            pytest.param(
                AT.load_sfn_template(AT.MAP_STATE_REFERENCE_IN_MAX_PER_BATCH_PATH),
                marks=pytest.mark.skip(
                    reason="TODO: Add JSONata support for ItemBatcher's MaxItemsPerBatch and MaxInputBytesPerBatch fields"
                ),
            ),
        ],
        ids=[
            "MAP_STATE_REFERENCE_IN_MAX_ITEMS_PATH",
            "MAP_STATE_REFERENCE_IN_MAX_PER_BATCH_PATH",
        ],
    )
    @markers.aws.validated
    def test_reference_in_map_state_max_items_path(
        self,
        aws_client,
        s3_create_bucket,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        template,
    ):
        bucket_name = s3_create_bucket()
        sfn_snapshot.add_transformer(RegexTransformer(bucket_name, "bucket-name"))

        key = "file.json"
        json_file = json.dumps(
            [
                {"verdict": "true", "statement_date": "6/11/2008", "statement_source": "speech"},
                {
                    "verdict": "false",
                    "statement_date": "6/7/2022",
                    "statement_source": "television",
                },
                {
                    "verdict": "mostly-true",
                    "statement_date": "5/18/2016",
                    "statement_source": "news",
                },
                {"verdict": "false", "statement_date": "5/18/2024", "statement_source": "x"},
            ]
        )
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body=json_file)

        definition = json.dumps(template)
        exec_input = json.dumps({"Bucket": bucket_name, "Key": key})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
