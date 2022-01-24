from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.utils import load_template_raw


def test_cdk_bootstrap(cfn_client, cleanup_stacks, cleanup_changesets, is_change_set_finished):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"

    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("cdk_bootstrap_v10.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]
    assert change_set_id
    assert stack_id

    try:
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        assert wait_until(is_change_set_finished(change_set_id), max_retries=5)
    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
