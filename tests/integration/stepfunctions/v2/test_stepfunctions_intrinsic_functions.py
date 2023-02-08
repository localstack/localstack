import json

import pytest

from localstack.services.stepfunctions.asl.utils.json_path import JSONPathUtils
from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.integration.stepfunctions.utils import await_execution_success, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestSnfIntrinsicFunctions:
    @staticmethod
    def _create_and_test_on_inputs(
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
        ift_template,
        input_values,
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(ift_template)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        for i, input_value in enumerate(input_values):
            exec_input_dict = {IFT.FUNCTION_INPUT_KEY: input_value}
            exec_input = json.dumps(exec_input_dict)

            exec_resp = stepfunctions_client.start_execution(
                stateMachineArn=state_machine_arn, input=exec_input
            )
            snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, i))
            execution_arn = exec_resp["executionArn"]

            await_execution_success(
                stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
            )

            exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
            snapshot.match(f"exec_hist_resp_{i}", exec_hist_resp)

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
        self._create_and_test_on_inputs(
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
        self._create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.JSON_TO_STRING,
            input_values_jsons,
        )

    def test_format_1(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        input_values = ["", " ", "HelloWorld", None, 1, 1.1, '{"Arg1": 1, "Arg2": []}']
        self._create_and_test_on_inputs(
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

        self._create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.FORMAT_2,
            input_values,
        )

    def test_array_0(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        self._create_and_test_on_inputs(
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
        self._create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_2,
            input_values,
        )

    def test_uuid(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(IFT.UUID)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        exec_resp = stepfunctions_client.start_execution(stateMachineArn=state_machine_arn)
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        output = JSONPathUtils.extract_json(
            "$..executionSucceededEventDetails..output", exec_hist_resp
        )
        uuid = json.loads(output)[IFT.FUNCTION_OUTPUT_KEY]
        snapshot.add_transformer(RegexTransformer(uuid, "generated-uuid"))

        snapshot.match("exec_hist_resp", exec_hist_resp)

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
        self._create_and_test_on_inputs(
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
        self._create_and_test_on_inputs(
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
        self._create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.ARRAY_RANGE,
            input_values,
        )
