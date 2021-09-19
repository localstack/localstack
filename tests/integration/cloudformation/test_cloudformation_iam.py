import jinja2

from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_delete_role_detaches_role_policy(
    cfn_client,
    iam_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    role_name = f"LsRole{short_uid()}"
    policy_name = f"LsPolicy{short_uid()}"
    template_rendered = jinja2.Template(load_template_raw("iam_role_policy.yaml")).render(
        role_name=role_name,
        policy_name=policy_name,
        include_policy=True,
    )

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

        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        assert len(attached_policies) > 0

        # nopolicy_template = jinja2.Template(load_template_raw("iam_role_policy.yaml")).render(
        #     role_name=role_name,
        #     policy_name=policy_name,
        #     include_policy=False,
        # )
        # nopolicy_changeset_name = f"change-set-{short_uid()}"
        # response = cfn_client.create_change_set(
        #     StackName=stack_name,
        #     ChangeSetName=nopolicy_changeset_name,
        #     TemplateBody=nopolicy_template,
        #     ChangeSetType="UPDATE",
        # )
        # change_set_id = response["Id"]
        # wait_until(is_change_set_created_and_available(change_set_id))
        # cfn_client.execute_change_set(ChangeSetName=change_set_id)
        # time.sleep(5)
        # wait_until(is_stack_created(stack_id))  # TODO: wrong format
        # wait_until(is_stack_deleted(stack_id))

        # TODO: need to update stack to delete only a single resource
        # attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        # assert len(attached_policies) == 0

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
