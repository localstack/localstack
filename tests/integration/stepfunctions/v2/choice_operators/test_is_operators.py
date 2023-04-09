import pytest

from tests.integration.stepfunctions.utils import is_old_provider
from tests.integration.stepfunctions.v2.choice_operators.utils import (
    TYPE_COMPARISONS,
    create_and_test_comparison_function,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestIsOperators:
    def test_is_boolean(self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsBoolean",
            comparisons=TYPE_COMPARISONS,
        )

    def test_is_null(self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsNull",
            comparisons=TYPE_COMPARISONS,
        )

    def test_is_numeric(self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsNumeric",
            comparisons=TYPE_COMPARISONS,
        )

    def test_is_present(self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsPresent",
            comparisons=TYPE_COMPARISONS,
        )

    def test_is_string(self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsString",
            comparisons=TYPE_COMPARISONS,
        )

    @pytest.mark.skip(reason="TODO: investigate IsTimestamp behaviour.")
    def test_is_timestamp(
        self, create_iam_role_for_sfn, create_state_machine, snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "IsTimestamp",
            comparisons=TYPE_COMPARISONS,
        )
