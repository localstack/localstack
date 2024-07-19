import json

from localstack.testing.pytest import markers
from localstack.testing.pytest.stepfunctions.utils import create_and_record_execution
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.aws.services.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

# TODO: test for validation errors, and boundary testing.


@markers.snapshot.skip_snapshot_verify(paths=["$..tracingConfiguration"])
class TestJsonManipulation:
    @markers.aws.validated
    def test_string_to_json(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
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
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.STRING_TO_JSON,
            input_values,
        )

    @markers.aws.validated
    def test_json_to_string(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
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
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.JSON_TO_STRING,
            input_values_jsons,
        )

    @markers.aws.validated
    def test_json_merge(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        merge_bindings = [
            ({"a": {"a1": 1, "a2": 2}, "b": 2, "d": 3}, {"a": {"a3": 1, "a4": 2}, "c": 3, "d": 4}),
        ]
        input_values = list()
        for fst, snd in merge_bindings:
            input_values.append({"fst": fst, "snd": snd})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.JSON_MERGE,
            input_values,
        )

    @markers.aws.validated
    def test_json_merge_escaped_argument(
        self,
        aws_client,
        create_iam_role_for_sfn,
        create_state_machine,
        sfn_snapshot,
    ):
        template = IFT.load_sfn_template(IFT.JSON_MERGE_ESCAPED_ARGUMENT)
        definition = json.dumps(template)

        exec_input = json.dumps({"input_field": {"constant_input_field": "constant_value"}})
        create_and_record_execution(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            definition,
            exec_input,
        )
