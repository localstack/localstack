import json
import os
import re

import jinja2
import pytest

from localstack.services.iam.provider import SERVICE_LINKED_ROLE_PATH_PREFIX
from localstack.testing.aws.cloudformation_utils import load_template_file
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until


# TODO: refactor file and remove this compatibility fn
def load_template_raw(file_name: str):
    return load_template_file(os.path.join(os.path.dirname(__file__), "../templates", file_name))


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


def test_policy_attachments(
    iam_client,
    deploy_cfn_template,
):
    role_name = f"role-{short_uid()}"
    group_name = f"group-{short_uid()}"
    user_name = f"user-{short_uid()}"
    policy_name = f"policy-{short_uid()}"

    linked_role_id = short_uid()
    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/iam_policy_attachments.yaml"
        ),
        template_mapping={
            "role_name": role_name,
            "policy_name": policy_name,
            "user_name": user_name,
            "group_name": group_name,
            "service_linked_role_id": linked_role_id,
        },
    )

    # check inline policies
    role_inline_policies = iam_client.list_role_policies(RoleName=role_name)
    user_inline_policies = iam_client.list_user_policies(UserName=user_name)
    group_inline_policies = iam_client.list_group_policies(GroupName=group_name)
    assert len(role_inline_policies["PolicyNames"]) == 1
    assert len(user_inline_policies["PolicyNames"]) == 1
    assert len(group_inline_policies["PolicyNames"]) == 1

    # check managed/attached policies
    role_attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)
    user_attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
    group_attached_policies = iam_client.list_attached_group_policies(GroupName=group_name)
    assert len(role_attached_policies["AttachedPolicies"]) == 1
    assert len(user_attached_policies["AttachedPolicies"]) == 1
    assert len(group_attached_policies["AttachedPolicies"]) == 1

    # check service linked roles
    roles = iam_client.list_roles(PathPrefix=SERVICE_LINKED_ROLE_PATH_PREFIX)["Roles"]
    matching = [r for r in roles if r["Description"] == f"service linked role {linked_role_id}"]
    assert matching
    policy = matching[0]["AssumeRolePolicyDocument"]
    policy = json.loads(policy) if isinstance(policy, str) else policy
    assert policy["Statement"][0]["Principal"] == {"Service": "elasticbeanstalk.amazonaws.com"}


@pytest.mark.aws_validated
def test_iam_username_defaultname(deploy_cfn_template, iam_client, snapshot):
    snapshot.skip_key(re.compile("UserId"), "<user-id>")

    template = json.dumps(
        {
            "Resources": {
                "DefaultNameUser": {
                    "Type": "AWS::IAM::User",
                }
            },
            "Outputs": {"DefaultNameUserOutput": {"Value": {"Ref": "DefaultNameUser"}}},
        }
    )
    stack = deploy_cfn_template(template=template)
    user_name = stack.outputs["DefaultNameUserOutput"]
    assert user_name

    get_iam_user = iam_client.get_user(UserName=user_name)
    snapshot.match("get_iam_user", get_iam_user)
