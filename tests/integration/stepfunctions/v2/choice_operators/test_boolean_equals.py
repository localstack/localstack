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
class TestBooleanEquals:
    def test_boolean_equals(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        create_and_test_comparison_function(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "BooleanEquals",
            comparisons=TYPE_COMPARISONS,
        )

    def test_boolean_equals_path(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        create_and_test_comparison_function(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            "BooleanEqualsPath",
            comparisons=TYPE_COMPARISONS,
            add_literal_value=False,
        )
