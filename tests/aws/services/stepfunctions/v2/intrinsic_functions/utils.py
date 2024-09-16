import json

from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.testing.pytest.stepfunctions.utils import await_execution_success
from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.templates.intrinsicfunctions.intrinsic_functions_templates import (
    IntrinsicFunctionTemplate as IFT,
)


def create_and_test_on_inputs(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    ift_template,
    input_values,
):
    snf_role_arn = create_iam_role_for_sfn()
    sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))

    sm_name: str = f"statemachine_{short_uid()}"
    definition = IFT.load_sfn_template(ift_template)
    definition_str = json.dumps(definition)

    creation_resp = create_state_machine(
        name=sm_name, definition=definition_str, roleArn=snf_role_arn
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
    state_machine_arn = creation_resp["stateMachineArn"]

    for i, input_value in enumerate(input_values):
        exec_input_dict = {IFT.FUNCTION_INPUT_KEY: input_value}
        exec_input = json.dumps(exec_input_dict)

        exec_resp = stepfunctions_client.start_execution(
            stateMachineArn=state_machine_arn, input=exec_input
        )
        sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, i))
        execution_arn = exec_resp["executionArn"]

        await_execution_success(
            stepfunctions_client=stepfunctions_client, execution_arn=execution_arn
        )

        exec_hist_resp = stepfunctions_client.get_execution_history(executionArn=execution_arn)
        sfn_snapshot.match(f"exec_hist_resp_{i}", exec_hist_resp)
