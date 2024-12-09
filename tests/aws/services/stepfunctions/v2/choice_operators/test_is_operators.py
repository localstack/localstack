import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.v2.choice_operators.utils import (
    TYPE_COMPARISONS,
    create_and_test_comparison_function,
)

# TODO: test for validation errors, and boundary testing.


class TestIsOperators:
    @markers.aws.validated
    def test_is_boolean(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsBoolean",
            comparisons=TYPE_COMPARISONS,
        )

    @markers.aws.validated
    def test_is_null(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsNull",
            comparisons=TYPE_COMPARISONS,
        )

    @markers.aws.validated
    def test_is_numeric(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsNumeric",
            comparisons=TYPE_COMPARISONS,
        )

    @markers.aws.validated
    def test_is_present(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsPresent",
            comparisons=TYPE_COMPARISONS,
        )

    @markers.aws.validated
    def test_is_string(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsString",
            comparisons=TYPE_COMPARISONS,
        )

    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="TODO: investigate IsTimestamp behaviour."
    )
    @markers.aws.needs_fixing
    def test_is_timestamp(
        self, create_state_machine_iam_role, create_state_machine, sfn_snapshot, aws_client
    ):
        create_and_test_comparison_function(
            aws_client,
            create_state_machine_iam_role,
            create_state_machine,
            sfn_snapshot,
            "IsTimestamp",
            comparisons=TYPE_COMPARISONS,
        )
