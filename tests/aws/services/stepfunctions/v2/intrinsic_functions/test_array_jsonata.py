from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestArrayJSONata:
    @markers.aws.validated
    def test_array_partition(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        # TODO: test and add support for raising exception on empty array.
        arrays = [list(range(i)) for i in range(1, 5)]
        input_values = list()
        for array in arrays:
            for chunk_size in range(1, 6):
                input_values.append({"fst": array, "snd": chunk_size})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ARRAY_PARTITION_JSONATA,
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
            IFT.ARRAY_RANGE_JSONATA,
            input_values,
        )
