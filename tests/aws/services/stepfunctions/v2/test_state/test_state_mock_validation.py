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
        # TODO choice
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
        aws_client_no_sync_prefix,
        sfn_snapshot,
        definition_template,
        mock,
    ):
        template = TST.load_sfn_template(definition_template)
        definition = json.dumps(template)

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    STATES_REQUIRING_MOCKS = [
        pytest.param(TST.BASE_MAP_STATE, id="MapState"),
        pytest.param(TST.MAP_TASK_STATE, id="MapTaskState"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("definition_template", STATES_REQUIRING_MOCKS)
    def test_state_type_requires_mock(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
        definition_template,
    ):
        template = TST.load_sfn_template(definition_template)
        definition = json.dumps(template)

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    @markers.aws.validated
    def test_both_mock_result_and_mock_error_output_are_set(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        mock = {
            "result": json.dumps({"mock": "response"}),
            "errorOutput": {"error": "Error", "cause": "Cause"},
        }

        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    @markers.aws.validated
    def test_reveal_secrets_is_true_and_mock_result_is_set(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TST.load_sfn_template(TST.BASE_LAMBDA_SERVICE_TASK_STATE)
        definition = json.dumps(template)
        mock = {"result": json.dumps({"mock": "response"})}
        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
                revealSecrets=True,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    @markers.aws.validated
    def test_mock_result_is_not_array_on_map_state_without_result_writer(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TST.load_sfn_template(TST.BASE_MAP_STATE)
        definition = json.dumps(template)
        mock = {"result": json.dumps({"mock": "array is expected but object is provided instead"})}
        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
            )
        sfn_snapshot.match("validation_exception", e.value.response)

    @markers.aws.validated
    def test_mock_result_is_not_object_on_map_state_with_result_writer(
        self,
        aws_client_no_sync_prefix,
        sfn_snapshot,
    ):
        template = TST.load_sfn_template(TST.BASE_MAP_STATE_WITH_RESULT_WRITER)
        definition = json.dumps(template)
        mock = {"result": json.dumps(["object is expected but array is provided instead"])}
        with pytest.raises(Exception) as e:
            aws_client_no_sync_prefix.stepfunctions.test_state(
                definition=definition,
                inspectionLevel=InspectionLevel.TRACE,
                mock=mock,
            )
        sfn_snapshot.match("validation_exception", e.value.response)
