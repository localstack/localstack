import pytest

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.utils import is_old_provider
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..loggingConfiguration", "$..tracingConfiguration"])
class TestStringOperations:
    @markers.aws.validated
    def test_string_split(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [
            {"fst": "1,2,3,4,5", "snd": ","},
            {"fst": "This.is+a,test=string", "snd": ".+,="},
        ]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.STRING_SPLIT,
            input_values,
        )
