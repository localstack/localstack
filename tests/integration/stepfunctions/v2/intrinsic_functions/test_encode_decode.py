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
class TestEncodeDecode:
    def test_base_64_encode(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = ["", "Data to encode"]
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.BASE_64_ENCODE,
            input_values,
        )

    def test_base_64_decode(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = ["", "RGF0YSB0byBlbmNvZGU="]
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.BASE_64_DECODE,
            input_values,
        )
