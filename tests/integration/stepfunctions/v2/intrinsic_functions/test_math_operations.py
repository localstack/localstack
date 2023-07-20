import json

import pytest

from localstack.testing.pytest.marking import Markers
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


@Markers.snapshot.skip_snapshot_verify(
    paths=["$..loggingConfiguration", "$..tracingConfiguration", "$..previousEventId"]
)
class TestMathOperations:
    def test_math_random(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..executionSucceededEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        start_end_tuples = [(12.50, 44.51), (9999, 99999), (-99999, -9999)]
        input_values = [{"fst": start, "snd": end} for start, end in start_end_tuples]

        for i, input_value in enumerate(input_values):
            exec_input_dict = {IFT.FUNCTION_INPUT_KEY: input_value}
            exec_input = json.dumps(exec_input_dict)

            exec_resp = aws_client.stepfunctions.start_execution(
                stateMachineArn=state_machine_arn, input=exec_input
            )
            sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, i))
            execution_arn = exec_resp["executionArn"]

            await_execution_success(
                stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
            )

            exec_hist_resp = aws_client.stepfunctions.get_execution_history(
                executionArn=execution_arn
            )
            sfn_snapshot.match(f"exec_hist_resp_{i}", exec_hist_resp)

    def test_math_random_seeded(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        snf_role_arn = create_iam_role_for_sfn()
        sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
        sfn_snapshot.add_transformer(
            JsonpathTransformer(
                "$..events..executionSucceededEventDetails.output.FunctionResult",
                "RandomNumberGenerated",
                replace_reference=False,
            )
        )
        sfn_snapshot.add_transformer(
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
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
        state_machine_arn = creation_resp["stateMachineArn"]

        input_value = {"fst": 0, "snd": 999, "trd": 3}
        exec_input_dict = {IFT.FUNCTION_INPUT_KEY: input_value}
        exec_input = json.dumps(exec_input_dict)

        exec_resp = aws_client.stepfunctions.start_execution(
            stateMachineArn=state_machine_arn, input=exec_input
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=aws_client.stepfunctions, execution_arn=execution_arn
        )

        exec_hist_resp = aws_client.stepfunctions.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match("exec_hist_resp", exec_hist_resp)

    def test_math_add(
        self, create_iam_role_for_sfn, create_state_machine, sfn_snapshot, aws_client
    ):
        add_tuples = [(-9, 3), (1.49, 1.50), (1.50, 1.51), (-1.49, -1.50), (-1.50, -1.51)]
        input_values = list()
        for fst, snd in add_tuples:
            input_values.append({"fst": fst, "snd": snd})
        create_and_test_on_inputs(
            aws_client.stepfunctions,
            create_iam_role_for_sfn,
            create_state_machine,
            sfn_snapshot,
            IFT.MATH_ADD,
            input_values,
        )
