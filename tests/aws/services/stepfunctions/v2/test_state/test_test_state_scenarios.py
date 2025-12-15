import json

import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.evaluatejsonata.evaluate_jsonata_templates import (
    EvaluateJsonataTemplate as EJT,
)
from tests.aws.services.stepfunctions.templates.services.services_templates import (
    ServicesTemplates as ST,
)
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateMachineTemplate as TSMT,
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
BASE_MAP_STATE_INPUT = json.dumps({"Values": [1, 2, 3]})

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
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.INFO,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tct_template,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    def test_base_inspection_level_debug(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.DEBUG,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tct_template,execution_input",
        BASE_TEMPLATE_INPUT_BINDINGS,
        ids=IDS_BASE_TEMPLATE_INPUT_BINDINGS,
    )
    def test_base_inspection_level_trace(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        create_state_machine,
        sfn_snapshot,
        tct_template,
        execution_input,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)

        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=execution_input,
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_lambda_task_state(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
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

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_base_lambda_service_task_state(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
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

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=inspection_level,
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    def test_base_lambda_service_task_state_no_role_arn_validation(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        function_name = f"lambda_func_{short_uid()}"
        sfn_snapshot.add_transformer(RegexTransformer(function_name, "<lambda_function_name>"))

        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        exec_input = json.dumps({"FunctionName": function_name, "Payload": None})

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=exec_input,
                inspectionLevel=InspectionLevel.TRACE,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    @pytest.mark.parametrize(
        "expression_dict",
        [
            {"MaxConcurrency": EJT.JSONATA_NUMBER_EXPRESSION},
            {"ToleratedFailurePercentage": EJT.JSONATA_NUMBER_EXPRESSION},
            {"ToleratedFailureCount": EJT.JSONATA_NUMBER_EXPRESSION},
        ],
        ids=[
            "MAX_CONCURRENCY",
            "TOLERATED_FAILURE_PERCENTAGE",
            "TOLERATED_FAILURE_COUNT",
        ],
    )
    def test_base_map_state_inspect(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        expression_dict,
        inspection_level,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.resource_name())

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        template = TST.load_sfn_template(TST.BASE_MAP_STATE)
        template.update(expression_dict)

        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=BASE_MAP_STATE_INPUT,
            inspectionLevel=inspection_level,
            mock={"result": json.dumps([1, 1, 1])},
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_state_task_catch_error(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.resource_name())

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        template = TST.load_sfn_template(TST.BASE_TASK_STATE_CATCH)
        definition = json.dumps(template)

        catch_mock_exception_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=HELLO_WORLD_INPUT,
            inspectionLevel=inspection_level,
            mock={
                "errorOutput": {"error": "MockException", "cause": "Mock the cause of the error."}
            },
        )

        sfn_snapshot.match("test_catch_mock_exception_response", catch_mock_exception_response)

        catch_task_failed_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=HELLO_WORLD_INPUT,
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "States.TaskFailed", "cause": "The task failed."}},
        )

        sfn_snapshot.match("catch_task_failed_response", catch_task_failed_response)

    @markers.aws.validated
    def test_localstack_blogpost_scenario(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        region_name,
    ):
        template = TSMT.load_sfn_template(TSMT.LOCALSTACK_BLOGPOST_SCENARIO_STATE_MACHINE)
        template["States"]["Ask for Approval"]["Arguments"]["ApiEndpoint"] = (
            f"example.execute-api.{region_name}.amazonaws.com"
        )
        definition = json.dumps(template)

        # Step 1 - Testing the Approval Required state
        # 1.1 Approval Required state correctly approves small purchases

        small_purchase_input = json.dumps({"cost": 9})

        small_purchase_approval_required_response = (
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=small_purchase_input,
                stateName="Approval Required",
                inspectionLevel=InspectionLevel.TRACE,
            )
        )
        sfn_snapshot.match(
            "small_purchase_approval_required_response", small_purchase_approval_required_response
        )

        # 1.2 Approval Required state correctly sends large purchases to the approval ask process

        large_purchase_input = json.dumps({"cost": 10})

        large_purchase_approval_required_response = (
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=large_purchase_input,
                stateName="Approval Required",
                inspectionLevel=InspectionLevel.TRACE,
            )
        )
        sfn_snapshot.match(
            "large_purchase_approval_required_response", large_purchase_approval_required_response
        )

        # Step 2 - Testing the Approval Ask state
        # Approval Ask state correctly approves large purchases

        large_purchase_input = json.dumps({"cost": 10})

        large_purchase_ask_for_approval_response = (
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                input=large_purchase_input,
                stateName="Ask for Approval",
                mock={"result": '{"approval": true }'},
                inspectionLevel=InspectionLevel.TRACE,
            )
        )
        sfn_snapshot.match(
            "large_purchase_ask_for_approval_response", large_purchase_ask_for_approval_response
        )

        # Step 3 - Testing the Check Approval state
        # 3.1 Approval granted

        check_approval_granted_input = json.dumps(
            {"approval": True, "approval_code": "2387462", "approved_by": "Mary"}
        )

        check_approval_granted_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=check_approval_granted_input,
            stateName="Check Approval",
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("check_approval_granted_response", check_approval_granted_response)

        # 3.2 Approval denied

        check_approval_denied_input = json.dumps({"approval": False})

        check_approval_denied_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=check_approval_denied_input,
            stateName="Check Approval",
            inspectionLevel=InspectionLevel.TRACE,
        )
        sfn_snapshot.match("check_approval_denied_response", check_approval_denied_response)
