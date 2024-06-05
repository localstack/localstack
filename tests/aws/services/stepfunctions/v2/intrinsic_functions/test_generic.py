import json

from localstack.testing.pytest import markers
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestGeneric:
    @markers.aws.validated
    def test_format_1(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = ["", " ", "HelloWorld", None, 1, 1.1, '{"Arg1": 1, "Arg2": []}']
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.FORMAT_1,
            input_values,
        )

    @markers.aws.validated
    def test_format_2(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
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
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.FORMAT_2,
            input_values,
        )

    @markers.aws.validated
    def test_context_json_path(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [None]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.FORMAT_CONTEXT_PATH,
            input_values,
        )

    @markers.aws.validated
    def test_nested_calls_1(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [None]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.NESTED_CALLS_1,
            input_values,
        )

    @markers.aws.validated
    def test_nested_calls_2(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [None]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.NESTED_CALLS_2,
            input_values,
        )

    @markers.aws.validated
    def test_escape_sequence(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        input_values = [None]
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.ESCAPE_SEQUENCE,
            input_values,
        )
