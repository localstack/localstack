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
class TestHashCalculations:
    @markers.aws.validated
    def test_hash(self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client):
        hash_bindings = [
            ("input data", "MD5"),
            ("input data", "SHA-1"),
            ("input data", "SHA-256"),
            ("input data", "SHA-384"),
            ("input data", "SHA-512"),
        ]
        input_values = [{"fst": inp, "snd": algo} for inp, algo in hash_bindings]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.HASH,
            input_values,
        )
