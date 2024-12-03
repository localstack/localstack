import pytest
from localstack_snapshot.snapshots.transformer import JsonpathTransformer, RegexTransformer

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs


class TestMathOperationsJSONata:
    @pytest.mark.skip(reason="AWS does not compute function randomSeeded")
    @markers.aws.validated
    def test_math_random_seeded(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                "$..FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                "$..FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        input_values = list({"fst": 3})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.MATH_RANDOM_SEEDED_JSONATA,
            input_values,
        )
