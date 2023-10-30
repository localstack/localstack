from typing import Any, Final

import pytest

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.utils import is_old_provider
from tests.aws.services.stepfunctions.v2.choice_operators.utils import (
    create_and_test_comparison_function,
)

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
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
    [],
    [""],
    {},
    {"A": 0},
    False,
    True,
]


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestStrings:
    @markers.aws.validated
    def test_string_equals(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        type_equals = []
        for var in TYPE_COMPARISONS_VARS:
            type_equals.append((var, "HelloWorld"))

        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "StringEquals",
            comparisons=[*type_equals, (" ", "     "), ("\t\n", "\t\r\n"), ("Hello", "Hello")],
        )

    @markers.aws.validated
    def test_string_equals_path(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        type_equals = []
        for var in TYPE_COMPARISONS_VARS:
            type_equals.append((var, 0))
            type_equals.append((var, 0.0))
            type_equals.append((var, 1))
            type_equals.append((var, 1.0))

        create_and_test_comparison_function(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            "StringEqualsPath",
            comparisons=[(" ", "     "), ("\t\n", "\t\r\n"), ("Hello", "Hello")],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_string_greater_than(
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
            "StringGreaterThan",
            comparisons=[("", ""), ("A", "A "), ("A", "A\t\n\r"), ("AB", "ABC")],
        )

    @markers.aws.validated
    def test_string_greater_than_path(
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
            "StringGreaterThanPath",
            comparisons=[("", ""), ("A", "A "), ("A", "A\t\n\r"), ("AB", "ABC")],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_string_greater_than_equals(
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
            "StringGreaterThanEquals",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
        )

    @markers.aws.validated
    def test_string_greater_than_equals_path(
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
            "StringGreaterThanEqualsPath",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_string_less_than(
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
            "StringLessThan",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
        )

    @markers.aws.validated
    def test_string_less_than_path(
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
            "StringLessThanPath",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
            add_literal_value=False,
        )

    @markers.aws.validated
    def test_string_less_than_equals(
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
            "StringLessThanEquals",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
        )

    @markers.aws.validated
    def test_string_less_than_equals_path(
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
            "StringLessThanEqualsPath",
            comparisons=[("", ""), ("A", "AB"), ("AB", "A")],
            add_literal_value=False,
        )
