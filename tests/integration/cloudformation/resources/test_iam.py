import json
import os

import pytest

from localstack.services.iam.provider import SERVICE_LINKED_ROLE_PATH_PREFIX
from localstack.utils.common import short_uid


def test_delete_role_detaches_role_policy(cfn_client, iam_client, deploy_cfn_template):
    role_name = f"LsRole{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/iam_role_policy.yaml"
        ),
        parameters={"RoleName": role_name},
    )
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
        "AttachedPolicies"
    ]
    assert len(attached_policies) > 0

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/iam_role_policy.yaml"
        ),
        parameters={"RoleName": f"role-{short_uid()}"},
    )

    with pytest.raises(Exception) as e:
        iam_client.list_attached_role_policies(RoleName=role_name)
    assert e.value.response.get("Error").get("Code") == "NoSuchEntity"


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
            os.path.dirname(__file__), "../../templates/iam_policy_attachments.yaml"
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
    assert len(role_inline_policies["PolicyNames"]) == 2
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
    matching = [r for r in roles if r.get("Description") == f"service linked role {linked_role_id}"]
    assert matching
    policy = matching[0]["AssumeRolePolicyDocument"]
    policy = json.loads(policy) if isinstance(policy, str) else policy
    assert policy["Statement"][0]["Principal"] == {"Service": "elasticbeanstalk.amazonaws.com"}


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..User.Tags"])
def test_iam_username_defaultname(deploy_cfn_template, iam_client, snapshot):
    snapshot.add_transformer(snapshot.transform.iam_api())
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

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


@pytest.mark.aws_validated
def test_iam_user_access_key(deploy_cfn_template, iam_client, snapshot):
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("AccessKeyId", "key-id"),
            snapshot.transform.key_value("UserName", "user-name"),
            snapshot.transform.key_value("SecretAccessKey", "secret-access-key"),
        ]
    )

    user_name = f"user-{short_uid()}"
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/iam_access_key.yaml"
        ),
        parameters={"UserName": user_name},
    )

    snapshot.match("key_outputs", stack.outputs)

    keys = iam_client.list_access_keys(UserName=user_name)["AccessKeyMetadata"]
    snapshot.match("access_key", keys[0])


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(
    paths=[
        "$..Policy.Description",
        "$..Policy.IsAttachable",
        "$..Policy.PermissionsBoundaryUsageCount",
        "$..Policy.Tags",
    ]
)
def test_managed_policy_with_empty_resource(iam_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(
        snapshot.transform.iam_api(),
    )
    snapshot.add_transformers_list(
        [snapshot.transform.resource_name(), snapshot.transform.key_value("PolicyId", "policy-id")]
    )

    parameters = {
        "tableName": f"table-{short_uid()}",
        "policyName": f"managed-policy-{short_uid()}",
    }

    template_path = os.path.join(os.path.dirname(__file__), "../../templates/dynamodb_iam.yaml")

    stack = deploy_cfn_template(template_path=template_path, parameters=parameters)

    snapshot.match("outputs", stack.outputs)

    policy_arn = stack.outputs["PolicyArn"]
    policy = iam_client.get_policy(PolicyArn=policy_arn)
    snapshot.match("managed_policy", policy)
