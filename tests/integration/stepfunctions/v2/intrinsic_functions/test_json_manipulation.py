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
class TestJsonManipulation:
    def test_string_to_json(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = [
            "",
            " ",
            "null",
            "-0",
            "1",
            "1.1",
            "true",
            '"HelloWorld"',
            '[1, 2, "HelloWorld"]',
            '{"Arg1": 1, "Arg2": []}',
        ]
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.STRING_TO_JSON,
            input_values,
        )

    def test_json_to_string(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = [
            "null",
            "-0",
            "1",
            "1.1",
            "true",
            '"HelloWorld"',
            '[1, 2, "HelloWorld"]',
            '{"Arg1": 1, "Arg2": []}',
        ]
        input_values_jsons = list(map(json.loads, input_values))
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.JSON_TO_STRING,
            input_values_jsons,
        )

    def test_json_merge(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        merge_bindings = [
            ({"a": {"a1": 1, "a2": 2}, "b": 2, "d": 3}, {"a": {"a3": 1, "a4": 2}, "c": 3, "d": 4}),
        ]
        input_values = list()
        for fst, snd in merge_bindings:
            input_values.append({"fst": fst, "snd": snd})
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.JSON_MERGE,
            input_values,
        )
