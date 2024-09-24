import json

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestArray:
    @markers.aws.validated
    def test_array_0(self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client):
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_0,
            ["HelloWorld"],
        )

    @markers.aws.validated
    def test_array_2(self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client):
        values = [
            "",
            " ",
            "HelloWorld",
            None,
            1,
            1.1,
            '{"Arg1": 1, "Arg2": []}',
            json.loads('{"Arg1": 1, "Arg2": []}'),
        ]
        input_values = list()
        for value in values:
            input_values.append({"fst": value, "snd": value})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_2,
            input_values,
        )

    @markers.aws.validated
    def test_array_partition(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        arrays = [list(range(i)) for i in range(5)]
        input_values = list()
        for array in arrays:
            for chunk_size in range(1, 6):
                input_values.append({"fst": array, "snd": chunk_size})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_PARTITION,
            input_values,
        )

    @markers.aws.validated
    def test_array_contains(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        search_bindings = [
            ([], None),
            ([], []),
            ([], 1),
            ([[1, 2, 3], 2], None),
            ([[1, 2, 3], 2], [1, 2, 3]),
            ([{1: 2, 2: []}], []),
            ([{1: 2, 2: []}], {1: 2, 2: []}),
            ([True, False], True),
            ([True, False], False),
        ]
        input_values = list()
        for array, value in search_bindings:
            input_values.append({"fst": array, "snd": value})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_CONTAINS,
            input_values,
        )

    @markers.aws.validated
    def test_array_range(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        ranges = [
            (0, 9, 3),
            (0, 10, 3),
            (1, 9, 9),
            (1, 9, 2),
        ]
        input_values = list()
        for fst, lst, step in ranges:
            input_values.append({"fst": fst, "snd": lst, "trd": step})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_RANGE,
            input_values,
        )

    @markers.aws.validated
    def test_array_get_item(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [{"fst": [1, 2, 3, 4, 5, 6, 7, 8, 9], "snd": 5}]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_GET_ITEM,
            input_values,
        )

    @markers.aws.validated
    def test_array_length(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [[1, 2, 3, 4, 5, 6, 7, 8, 9]]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_LENGTH,
            input_values,
        )

    @markers.aws.validated
    def test_array_unique(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [
            [
                None,
                None,
                True,
                True,
                False,
                False,
                1,
                1,
                1.1,
                0,
                -0,
                "HelloWorld",
                "HelloWorld",
                [],
                [],
                [None],
                [None],
                {"a": 1, "b": 2},
                {"a": 1, "b": 2},
                {"a": 1, "b": 1},
            ]
        ]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_LENGTH,
            input_values,
        )
