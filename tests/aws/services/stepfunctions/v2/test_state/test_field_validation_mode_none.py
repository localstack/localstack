import json

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestFieldValidationModeNone:
    SFN_VALIDATION_ERRORS = [
        pytest.param(
            {},
            id="missing_required_fields",
        ),
        pytest.param(
            {"ExecutionArn": "stringValueExecutionArn", "StartDate": True},
            id="wrong_timestamp_type_bool",
        ),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", SFN_VALIDATION_ERRORS)
    def test_none_mode_sfn_task(
        self,
        aws_client_no_sync_prefix,
        account_id,
        region_name,
        sfn_snapshot,
        result,
    ):
        template = TST.load_sfn_template(TST.BASE_SFN_START_EXECUTION_TASK_STATE)
        definition = json.dumps(template)

        target_state_machine_arn = arns.stepfunctions_state_machine_arn(
            name="TargetStateMachine", account_id=account_id, region_name=region_name
        )

        target_execution_name = "TestStartTarget"

        exec_input = json.dumps(
            {
                "stateMachineArn": target_state_machine_arn,
                "targetInput": None,
                "name": target_execution_name,
            }
        )

        mock = {"result": json.dumps(result), "fieldValidationMode": "NONE"}

        test_state_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_state_response", test_state_response)
