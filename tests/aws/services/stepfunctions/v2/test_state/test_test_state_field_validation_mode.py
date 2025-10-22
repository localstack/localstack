import json

import pytest

from localstack.aws.api.stepfunctions import InspectionLevel
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.test_state.test_state_templates import (
    TestStateTemplate as TST,
)


class TestStateMockFieldValidationMode:
    """
    WIP. Moved relevant test cases from success scenarios to avoid deleting them. To be extended with more scenarios.

    TODO test cases and edge cases found out in the wild that are good candidates for tests
    - lambda response payload is not a string but a JSON - results in a validation error against the API spec
    - somehow in SQS SendMessage response the following mock {"MD5OfMessageBody": {"unexpected": ["object"]}} while the API spec requires {"MD5OfMessageBody": "string"}.
        At the same time, MessageId is validated to be a string. Both fields are in the API spec and both are strings there.
    - ...TBC
    """

    MOCK_VALUES_EVENTS = [
        pytest.param({"random": "json"}, id="field_not_part_of_api_spec"),
        pytest.param({}, id="empty_json"),
        # pytest.param("Hello World", id="simple_string"), TODO validate these general failure modes in a validation parity test
        # pytest.param(42, id="simple_number"),
        # pytest.param(["a", "b", "c"], id="simple_list"),
    ]

    @markers.aws.validated
    @pytest.mark.parametrize("result", MOCK_VALUES_EVENTS)
    def test_strict_mode_mock_result_field_not_in_api_spec(
        self,
        aws_client,
        aws_client_no_sync_prefix,
        create_state_machine_iam_role,
        sfn_snapshot,
        result,
    ):
        """
        Only fields from the API spec are validated
        """
        template = TST.load_sfn_template(TST.BASE_EVENTS_PUT_EVENTS_TASK_STATE)
        definition = json.dumps(template)

        entries = [
            {
                "Detail": "detail",
                "DetailType": "detail_type",
                "Source": "source",
            },
        ]
        exec_input = json.dumps({"Entries": entries})

        mock = {"result": json.dumps(result)}

        sfn_role_arn = create_state_machine_iam_role(aws_client)

        test_case_response = aws_client_no_sync_prefix.stepfunctions.test_state(
            definition=definition,
            roleArn=sfn_role_arn,
            input=exec_input,
            inspectionLevel=InspectionLevel.INFO,
            mock=mock,
        )
        sfn_snapshot.match("test_case_response", test_case_response)
