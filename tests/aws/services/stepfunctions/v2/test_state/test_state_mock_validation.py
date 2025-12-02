import json

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestStateMockValidation:
    STATES_NOT_ACCEPTING_MOCKS = [
        pytest.param(TST.BASE_PASS_STATE, id="PassState"),
        pytest.param(TST.BASE_FAIL_STATE, id="FailState"),
        pytest.param(TST.BASE_SUCCEED_STATE, id="SucceedState"),
    ]
    MOCK_VARIANTS = [
        pytest.param({"result": json.dumps({"mock": "the unmockable"})}, id="mock_result"),
        pytest.param({"errorOutput": {"error": "Error", "cause": "Cause"}}, id="mock_error_output"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("definition_template", STATES_NOT_ACCEPTING_MOCKS)
    @pytest.mark.parametrize("mock", MOCK_VARIANTS)
    def test_state_type_does_not_accept_mock(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        definition_template,
        mock,
    ):
        template = TST.load_sfn_template(definition_template)
        definition = json.dumps(template)

        sfn_role_arn = create_state_machine_iam_role(aws_client)

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                roleArn=sfn_role_arn,
                # input=exec_input,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
            )
        sfn_snapshot.match("validation_exception", e.value.response)
