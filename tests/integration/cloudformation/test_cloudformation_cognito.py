import os

import jinja2
import pytest

from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until
from tests.integration.cloudformation.utils import load_template_raw


@pytest.mark.skipif(
    not bool(os.environ.get("LOCALSTACK_API_KEY")),
    reason="test uses pro features, skipped if no pro",
)
def test_cognito_role_attachement(
    cfn_client,
    cognito_identity_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    user_pool_name = f"user-pool-name-{short_uid()}"
    identity_pool_name = f"identity-pool-name-{short_uid()}"
    template_rendered = jinja2.Template(
        load_template_raw("cognito_identity_pool_role_attachement.yaml")
    ).render(user_pool_name=user_pool_name, identity_pool_name=identity_pool_name)

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
        final_stack = cfn_client.describe_stacks(StackName=stack_id)
        assert final_stack["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE"
        identity_pool_id = final_stack["Stacks"][0]["Outputs"][2]["OutputValue"]
        roles = cognito_identity_client.get_identity_pool_roles(IdentityPoolId=identity_pool_id)
        assert roles["RoleMappings"]

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
