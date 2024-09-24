import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)

HELLO_WORLD_INPUT = json.dumps({"Value": "HelloWorld"})
NESTED_DICT_INPUT = json.dumps(
    {
        "initialData": {"fieldFromInput": "value from input", "otherField": "other"},
        "unrelatedData": {"someOtherField": 1234},
    }
)
BASE_CHOICE_STATE_INPUT = json.dumps({"type": "Private", "value": 22})

BASE_TEMPLATE_INPUT_BINDINGS: list[tuple[str, str]] = [
    (TST.BASE_PASS_STATE, HELLO_WORLD_INPUT),
    (TST.BASE_RESULT_PASS_STATE, HELLO_WORLD_INPUT),
    (TST.IO_PASS_STATE, NESTED_DICT_INPUT),
    (TST.IO_RESULT_PASS_STATE, NESTED_DICT_INPUT),
    (TST.BASE_FAIL_STATE, HELLO_WORLD_INPUT),
    (TST.BASE_SUCCEED_STATE, HELLO_WORLD_INPUT),
    (TST.BASE_CHOICE_STATE, BASE_CHOICE_STATE_INPUT),
]
IDS_BASE_TEMPLATE_INPUT_BINDINGS: list[str] = [
    "BASE_PASS_STATE",
    "BASE_RESULT_PASS_STATE",
    "IO_PASS_STATE",
    "IO_RESULT_PASS_STATE",
    "BASE_FAIL_STATE",
    "BASE_SUCCEED_STATE",
    "BASE_CHOICE_STATE",
]


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..tracingConfiguration",
        "$..SdkHttpMetadata",
        "$..SdkResponseMetadata",
    ]
)
class TestStateCaseScenarios:
    # TODO: consider aggregating all `test_base_inspection_level_*` into a single parametrised function, and evaluate
    #  solutions for snapshot skips and parametrisation complexity.

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tct_template,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    def test_base_inspection_level_info(
        self,
        stepfunctions_client_test_state,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_iam_role_for_sfn()

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = stepfunctions_client_test_state.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generalisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    @pytest.mark.parametrize(
        "tct_template,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    def test_base_inspection_level_debug(
        self,
        stepfunctions_client_test_state,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_iam_role_for_sfn()

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = stepfunctions_client_test_state.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generalisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers. Such as ResultSelector, which is neither defined in
            # this Pass state, nor supported by Pass states.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    @pytest.mark.parametrize(
        "tct_template,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    def test_base_inspection_level_trace(
        self,
        stepfunctions_client_test_state,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_iam_role_for_sfn()

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = stepfunctions_client_test_state.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generalisable behaviour by AWS leads to the outputting of undeclared and
            # unsupported state modifiers.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterParameters",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_lambda_task_state(
        self,
        stepfunctions_client_test_state,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
        inspection_level,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_1_res = create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_RETURN_BYTES_STR,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TST.load_sfn_template(TST.BASE_LAMBDA_TASK_STATE)
        template["Resource"] = create_1_res["CreateFunctionResponse"]["FunctionArn"]
        definition = json.dumps(template)
        exec_input = json.dumps({"inputData": "HelloWorld"})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_response = stepfunctions_client_test_state.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Unknown generalisable behaviour by AWS leads to the outputting of undeclared state modifiers.
            "$..inspectionData.afterInputPath",
            "$..inspectionData.afterResultPath",
            "$..inspectionData.afterResultSelector",
        ]
    )
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_lambda_service_task_state(
        self,
        stepfunctions_client_test_state,
        create_iam_role_for_sfn,
        create_state_machine,
        create_lambda_function,
        sfn_snapshot,
        inspection_level,
    ):
        function_name = f"lambda_func_{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=ST.LAMBDA_ID_FUNCTION,
            runtime=Runtime.python3_12,
        )
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})

        sfn_role_arn = create_iam_role_for_sfn()
        test_case_response = stepfunctions_client_test_state.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)
