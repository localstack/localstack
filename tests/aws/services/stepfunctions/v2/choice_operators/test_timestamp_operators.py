from typing import Any, Final

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.v2.choice_operators.utils import (
    create_and_test_comparison_function,
)

# TODO: test for validation errors, and boundary testing.

TYPE_COMPARISONS_VARS: Final[list[Any]] = [
    None,
    0,
    0.0,
    1,
    1.1,
    "",
    " ",
    "2023-02-24 12:15:56.832957",
    [],
    [""],
    {},
    {"A": 0},
    False,
    True,
]

T0: Final[str] = "2012-10-09T19:00:55Z"
T1: Final[str] = "2012-10-09T19:00:56Z"
BASE_COMPARISONS: Final[list[tuple[str, str]]] = [(T0, T0), (T0, T1), (T1, T0)]


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestTimestamps:
    @markers.aws.validated
    def test_timestamp_equals(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        type_equals = []
        for var in TYPE_COMPARISONS_VARS:
            type_equals.append((var, T0))

        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampEquals",
            comparisons=[*type_equals, *BASE_COMPARISONS],
        )

    @markers.aws.validated
    def test_timestamp_equals_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampEqualsPath",
            comparisons=BASE_COMPARISONS,
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_timestamp_greater_than(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampGreaterThan",
            comparisons=BASE_COMPARISONS,
        )

    @markers.aws.validated
    def test_timestamp_greater_than_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampGreaterThanPath",
            comparisons=[(T0, T1)],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_timestamp_greater_than_equals(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampGreaterThanEquals",
            comparisons=BASE_COMPARISONS,
        )

    @markers.aws.validated
    def test_timestamp_greater_than_equals_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampGreaterThanEqualsPath",
            comparisons=[(T0, T1)],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_timestamp_less_than(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampLessThan",
            comparisons=BASE_COMPARISONS,
        )

    @markers.aws.validated
    def test_timestamp_less_than_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampLessThanPath",
            comparisons=[(T1, T0)],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_timestamp_less_than_equals(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampLessThanEquals",
            comparisons=BASE_COMPARISONS,
        )

    @markers.aws.validated
    def test_timestamp_less_than_equals_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "TimestampLessThanEqualsPath",
            comparisons=[(T1, T0)],
            add_literal_value=False,
        )
