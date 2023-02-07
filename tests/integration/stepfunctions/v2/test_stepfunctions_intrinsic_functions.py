import json

import pytest

from localstack.testing.snapshots.transformer import RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.integration.stepfunctions.utils import await_execution_success, is_old_provider

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


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
