import pytest

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.utils import is_old_provider
from tests.aws.services.stepfunctions.v2.choice_operators.utils import (
    TYPE_COMPARISONS,
    create_and_test_comparison_function,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestBooleanEquals:
    @markers.aws.validated
    def test_boolean_equals(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "BooleanEquals",
            comparisons=TYPE_COMPARISONS,
        )

    @markers.aws.validated
    def test_boolean_equals_path(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "BooleanEqualsPath",
            comparisons=TYPE_COMPARISONS,
            add_literal_value=False,
        )
