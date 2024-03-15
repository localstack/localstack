from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.utils.strings import short_uid
from tests.aws.services.stepfunctions.utils import await_execution_success


@staticmethod
def _test_sfn_scenario(
    stepfunctions_client,
    create_iam_role_for_sfn,
    create_state_machine,
    sfn_snapshot,
    definition,
    execution_input,
):
    snf_role_arn = create_iam_role_for_sfn()
    sfn_snapshot.add_transformer(RegexTransformer(snf_role_arn, "snf_role_arn"))
    sfn_snapshot.add_transformer(
        RegexTransformer(
            "Extended Request ID: [a-zA-Z0-9-/=+]+",
            "Extended Request ID: <extended_request_id>",
        )
    )
    sfn_snapshot.add_transformer(
        RegexTransformer("Request ID: [a-zA-Z0-9-]+", "Request ID: <request_id>")
    )

    sm_name: str = f"statemachine_{short_uid()}"
    creation_resp = create_state_machine(name=sm_name, definition=definition, roleArn=snf_role_arn)
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_create_arn(creation_resp, 0))
    state_machine_arn = creation_resp["stateMachineArn"]

    exec_resp = stepfunctions_client.start_execution(
        stateMachineArn=state_machine_arn, input=execution_input
    )
    sfn_snapshot.add_transformer(sfn_snapshot.transform.sfn_sm_exec_arn(exec_resp, 0))
    execution_arn = exec_resp["executionArn"]

    await_execution_success(stepfunctions_client=stepfunctions_client, execution_arn=execution_arn)

    get_execution_history = stepfunctions_client.get_execution_history(executionArn=execution_arn)
    sfn_snapshot.match("get_execution_history", get_execution_history)
