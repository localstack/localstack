from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_sqs_queue_policy(
    cfn_client,
    sqs_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    template_rendered = load_template_raw("sqs_with_queuepolicy.yaml")
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=template_rendered,
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))
        outputs = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
        assert len(outputs) == 1
        queue_url = outputs[0]["OutputValue"]
        resp = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
        assert (
            "Statement" in resp["Attributes"]["Policy"]
        )  # just kind of a smoke test to see if its set

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
