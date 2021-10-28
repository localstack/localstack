import os

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))


def test_statemachine_definitionsubstitution(
    cfn_client,
    lambda_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    stepfunctions_client,
    s3_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("stepfunctions_statemachine_substitutions.yaml"),
        ChangeSetType="CREATE",
        Capabilities=["CAPABILITY_IAM"],
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)

        wait_until(is_stack_created(stack_id))

        stack_result = cfn_client.describe_stacks(StackName=stack_id)
        assert stack_result["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"

        outputs = stack_result["Stacks"][0]["Outputs"]
        assert len(outputs) == 1
        statemachine_arn = outputs[0]["OutputValue"]

        # execute statemachine
        ex_result = stepfunctions_client.start_execution(stateMachineArn=statemachine_arn)

        def _is_executed():
            return (
                stepfunctions_client.describe_execution(executionArn=ex_result["executionArn"])[
                    "status"
                ]
                != "RUNNING"
            )

        wait_until(_is_executed)
        execution_desc = stepfunctions_client.describe_execution(
            executionArn=ex_result["executionArn"]
        )
        assert execution_desc["status"] == "SUCCEEDED"
        # sync execution is currently not supported since botocore adds a "sync-" prefix
        # ex_result = stepfunctions_client.start_sync_execution(stateMachineArn=statemachine_arn)

        assert "hello from statemachine" in execution_desc["output"]

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
