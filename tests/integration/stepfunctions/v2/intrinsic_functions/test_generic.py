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
class TestGeneric:
    def test_format_1(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = ["", " ", "HelloWorld", None, 1, 1.1, '{"Arg1": 1, "Arg2": []}']
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.FORMAT_1,
            input_values,
        )

    def test_format_2(
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
            IFT.FORMAT_2,
            input_values,
        )
