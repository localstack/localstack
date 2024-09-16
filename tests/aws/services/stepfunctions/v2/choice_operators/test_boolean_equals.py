from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.v2.choice_operators.utils import (
    TYPE_COMPARISONS,
    create_and_test_comparison_function,
)

# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
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
