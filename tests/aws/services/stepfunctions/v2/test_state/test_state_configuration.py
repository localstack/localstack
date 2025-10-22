import json
from typing import Final

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateMachineTemplate as TSMT,
)
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)

TEST_STATE_NAME: Final[str] = "TestState"

DEFAULT_INPUT = json.dumps({"Values": ["first", "second", "third"]})

BASE_TEMPLATE_BINDINGS: list[str] = [
    TST.BASE_MAP_STATE,
    TST.BASE_MAP_STATE_CATCH,
    TST.BASE_MAP_STATE_RETRY,
    TST.MAP_TASK_STATE,
]

IDS_BASE_TEMPLATE_BINDINGS: list[str] = [
    "BASE_MAP_STATE",
    "BASE_MAP_STATE_CATCH",
    "BASE_MAP_STATE_RETRY",
    "MAP_TASK_STATE",
]


class TestStateConfiguration:
    @markers.aws.validated
    @pytest.mark.parametrize("tct_template", BASE_TEMPLATE_BINDINGS, ids=IDS_BASE_TEMPLATE_BINDINGS)
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_map_state_failure_count(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
        tct_template,
    ):
        sfn_snapshot.add_transformer(sfn_snapshot.transform.resource_name())

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        template = TST.load_sfn_template(tct_template)
        definition = json.dumps(template)

        below_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={"mapIterationFailureCount": 0},
            inspectionLevel=inspection_level,
            mock={"result": json.dumps([1, 1, 1])},
        )
        sfn_snapshot.match("below_tolerated_failure", below_tolerated_failure)

        exceeds_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={"mapIterationFailureCount": 2},
            inspectionLevel=inspection_level,
            mock={"result": json.dumps([0, 0, 1])},
        )
        sfn_snapshot.match("exceeds_tolerated_failure", exceeds_tolerated_failure)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_map_state_error_caused_by_state(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        test_input = [1, 1, 1]

        sfn_role_arn = create_state_machine_iam_role(aws_client)
        template = TST.load_sfn_template(TST.BASE_MAP_STATE)
        definition = json.dumps(template)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=json.dumps({"Values": test_input}),
            stateConfiguration={
                "errorCausedByState": TEST_STATE_NAME,
            },
            inspectionLevel=inspection_level,
            mock={
                "errorOutput": {"error": "MockException", "cause": "Mock the cause of the error."}
            },
        )

        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize("inspection_level", [InspectionLevel.DEBUG, InspectionLevel.TRACE])
    def test_state_configuration_retrier_retry_count(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        template = TST.load_sfn_template(TST.BASE_TASK_STATE_RETRY)
        definition = json.dumps(template)

        below_tolerated_retry_count_with_backoff = (
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                roleArn=sfn_role_arn,
                input=DEFAULT_INPUT,
                stateConfiguration={
                    "retrierRetryCount": 4,
                },
                inspectionLevel=inspection_level,
                mock={
                    "errorOutput": {
                        "error": "MockException",
                        "cause": "Mock the cause of the error.",
                    }
                },
            )
        )

        sfn_snapshot.match(
            "below_tolerated_retry_count_with_backoff", below_tolerated_retry_count_with_backoff
        )

        exceeds_tolerated_retry_count = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={
                "retrierRetryCount": 5,
            },
            inspectionLevel=inspection_level,
            mock={
                "errorOutput": {"error": "MockException", "cause": "Mock the cause of the error."}
            },
        )

        sfn_snapshot.match("exceeds_tolerated_retry_count", exceeds_tolerated_retry_count)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_state_configuration_map_iteration_failure_count_with_state_error(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)

        template = TST.load_sfn_template(TST.BASE_MAP_STATE)
        definition = json.dumps(template)

        below_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={
                "mapIterationFailureCount": 0,
                "errorCausedByState": "TestState",
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("below_tolerated_failure", below_tolerated_failure)

        exceeds_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={
                "mapIterationFailureCount": 2,
                "errorCausedByState": "TestState",
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("exceeds_tolerated_failure", exceeds_tolerated_failure)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_state_machine_with_state_error(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)

        template = TSMT.load_sfn_template(TSMT.BASE_MAP_STATE_MACHINE)
        definition = json.dumps(template)

        below_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName="State0",
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={
                "mapIterationFailureCount": 0,
                "errorCausedByState": "HandleItem",
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("below_tolerated_failure", below_tolerated_failure)

        exceeds_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName="State0",
            definition=definition,
            roleArn=sfn_role_arn,
            input=DEFAULT_INPUT,
            stateConfiguration={
                "mapIterationFailureCount": 2,
                "errorCausedByState": "HandleItem",
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("exceeds_tolerated_failure", exceeds_tolerated_failure)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_state_machine_configuration_map_iteration_item_reader(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        exec_input = json.dumps({"Bucket": "test-bucket", "Key": "test-key"})

        template = TSMT.load_sfn_template(TSMT.MAP_ITEM_READER_STATE_MACHINE)
        definition = json.dumps(template)
        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName="State0",
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            stateConfiguration={
                "mapItemReaderData": json.dumps([1, 2, 3]),
            },
            inspectionLevel=inspection_level,
            mock={"result": json.dumps([1, 4, 9])},
        )
        sfn_snapshot.match("test_case_response", test_case_response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "inspection_level", [InspectionLevel.INFO, InspectionLevel.DEBUG, InspectionLevel.TRACE]
    )
    def test_state_machine_configuration_item_reader_with_error(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        inspection_level,
    ):
        sfn_role_arn = create_state_machine_iam_role(aws_client)
        exec_input = json.dumps({"Bucket": "test-bucket", "Key": "test-key"})

        template = TSMT.load_sfn_template(TSMT.MAP_ITEM_READER_STATE_MACHINE)
        definition = json.dumps(template)
        below_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName="State0",
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            stateConfiguration={
                "mapIterationFailureCount": 0,
                "errorCausedByState": "HandleItem",
                "mapItemReaderData": json.dumps([1, 2, 3]),
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("below_tolerated_failure", below_tolerated_failure)

        exceeds_tolerated_failure = aws_client_no_sync_prefix.stepfunctions.test_state(
            stateName="State0",
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            stateConfiguration={
                "mapIterationFailureCount": 2,
                "errorCausedByState": "HandleItem",
                "mapItemReaderData": json.dumps([1, 2, 3]),
            },
            inspectionLevel=inspection_level,
            mock={"errorOutput": {"error": "MockException", "cause": "Mock the error cause."}},
        )
        sfn_snapshot.match("exceeds_tolerated_failure", exceeds_tolerated_failure)
