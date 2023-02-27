import json

import pytest

from tests.integration.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.integration.stepfunctions.utils import is_old_provider
from tests.integration.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestArray:
    def test_array_0(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_0,
            ["HelloWorld"],
        )

    def test_array_2(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
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
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_2,
            input_values,
        )

    def test_array_partition(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        arrays = [list(range(i)) for i in range(5)]
        input_values = list()
        for array in arrays:
            for chunk_size in range(1, 6):
                input_values.append({"fst": array, "snd": chunk_size})
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_PARTITION,
            input_values,
        )

    def test_array_contains(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
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
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_CONTAINS,
            input_values,
        )

    def test_array_range(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
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
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_RANGE,
            input_values,
        )

    def test_array_get_item(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = [{"fst": [1, 2, 3, 4, 5, 6, 7, 8, 9], "snd": 5}]
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_GET_ITEM,
            input_values,
        )

    def test_array_length(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = [[1, 2, 3, 4, 5, 6, 7, 8, 9]]
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_LENGTH,
            input_values,
        )

    def test_array_unique(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
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
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_LENGTH,
            input_values,
        )
