import json

import pytest

from localstack.testing.snapshots.transformer import JsonpathTransformer, RegexTransformer
from localstack.utils.strings import short_uid
from tests.integration.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)
from tests.integration.stepfunctions.utils import await_execution_success, is_old_provider
from tests.integration.stepfunctions.v2.intrinsic_functions.utils import create_and_test_on_inputs

pytestmark = pytest.mark.skipif(
    condition=is_old_provider(), reason="Test suite for v2 provider only."
)


# TODO: test for validation errors, and boundary testing.


@pytest.mark.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestMathOperations:
    def test_math_random(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..executionSucceededEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..stateExitedEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(IFT.MATH_RANDOM)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        start_end_tuples = [(12.50, 44.51), (9999, 99999), (-99999, -9999)]
        input_values = [{"fst": start, "snd": end} for start, end in start_end_tuples]

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

    def test_math_random_seeded(
        self, stepfunctions_client, create_iam_role_for_sfn, create_state_machine, snapshot
    ):
        snf_role_arn = create_iam_role_for_sfn()
        snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..executionSucceededEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..stateExitedEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )

        sm_name: str = f"statemachine_{short_uid()}"
        definition = IFT.load_sfn_template(IFT.MATH_RANDOM_SEEDED)
        definition_str = json.dumps(definition)

        creation_resp = create_state_machine(
            name=sm_name, definition=definition_str, roleArn=snf_role_arn
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        input_value = {"fst": 0, "snd": 999, "trd": 3}
        exec_input_dict = {IFT.FUNCTION_INPUT_KEY: input_value}
        exec_input = json.dumps(exec_input_dict)

        exec_resp = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input=exec_input
        )
        snapshot.add_transformer(snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        snapshot.match("exec_hist_resp", exec_hist_resp)

    def test_math_add(
        self,
        stepfunctions_client,
        create_iam_role_for_sfn,
        create_state_machine,
        snapshot,
    ):
        add_tuples = [(-9, 3), (1.49, 1.50), (1.50, 1.51), (-1.49, -1.50), (-1.50, -1.51)]
        input_values = list()
        for fst, snd in add_tuples:
            input_values.append({"fst": fst, "snd": snd})
        create_and_test_on_inputs(
            stepfunctions_client,
            create_iam_role_for_sfn,
            create_state_machine,
            snapshot,
            IFT.MATH_ADD,
            input_values,
        )
