import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

MOCK_POLICY = {
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": "s3:ListBucket",
        "Resource": "arn:aws:s3:::example_bucket",
    },
}


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.iam_api())


# TODO properly test role last used
class TestRoleLifecycle:
    @markers.aws.validated
    def test_role_errors(self, aws_client, create_role, snapshot):
        """Test NoSuchEntity errors for get_role, update_role, delete_role on non-existent role."""
        role_name = "test-nonexistent-role"

        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.update_role(RoleName=role_name, Description="test")
        snapshot.match("update-role-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role(RoleName=role_name)
        snapshot.match("delete-role-error", e.value.response)

    @markers.aws.validated
    def test_create_role_defaults(self, aws_client, create_role, snapshot):
        """Verify default values for a role"""
        role_name = f"role-{short_uid()}"

        create_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )
        snapshot.match("create-role-response", create_response)

        get_response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-response", get_response)

    @markers.aws.validated
    def test_create_describe_role(self, snapshot, aws_client, create_role, cleanups):
        snapshot.add_transformer(snapshot.transform.iam_api())
        path_prefix = f"/{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path_prefix, "/<path-prefix>/"))

        role_name = f"role-{short_uid()}"
        create_role_result = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY), Path=path_prefix
        )
        snapshot.match("create-role-result", create_role_result)
        get_role_result = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-result", get_role_result)

        list_roles_result = aws_client.iam.list_roles(PathPrefix=path_prefix)
        snapshot.match("list-roles-result", list_roles_result)

    @markers.aws.validated
    def test_delete_role_with_attached_policy(
        self, aws_client, create_role, create_policy, snapshot
    ):
        """Test that deleting a role with attached managed policy fails with DeleteConflict."""
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"

        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )
        snapshot.match("create-role", create_role_response)

        policy_response = create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )
        policy_arn = policy_response["Policy"]["Arn"]

        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role(RoleName=role_name)
        snapshot.match("delete-role-with-policy-error", e.value.response)

        # detach the policy and delete the role
        aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        aws_client.iam.delete_role(RoleName=role_name)
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-after-deletion-error", e.value.response)

    @markers.aws.validated
    def test_delete_role_with_inline_policy(self, aws_client, create_role, snapshot):
        """Test that deleting a role with inline policy fails with DeleteConflict."""
        role_name = f"role-{short_uid()}"
        policy_name = f"inline-policy-{short_uid()}"

        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )
        snapshot.match("create-role", create_role_response)

        aws_client.iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )

        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role(RoleName=role_name)
        snapshot.match("delete-role-with-inline-policy-error", e.value.response)

        # delete the inline policy and delete the role
        aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        aws_client.iam.delete_role(RoleName=role_name)
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-after-deletion-error", e.value.response)

    @markers.aws.validated
    def test_update_role(self, aws_client, create_role, snapshot):
        """Test update_role and update_role_description operations."""
        role_name = f"role-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            Description="initial description",
        )

        # Get initial role state
        get_role_initial = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-initial", get_role_initial)

        # Update role with Description and MaxSessionDuration
        update_response = aws_client.iam.update_role(
            RoleName=role_name,
            Description="updated description",
            MaxSessionDuration=7200,
        )
        snapshot.match("update-role-response", update_response)

        # Get role after update
        get_role_after_update = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-after-update", get_role_after_update)

        # Update role description using update_role_description
        update_desc_response = aws_client.iam.update_role_description(
            RoleName=role_name,
            Description="description via update_role_description",
        )
        snapshot.match("update-role-description-response", update_desc_response)

        # Get role after update_role_description
        get_role_after_desc_update = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-after-desc-update", get_role_after_desc_update)

    @markers.aws.validated
    def test_update_assume_role_policy_errors(self, aws_client, create_role, snapshot):
        """Test update_assume_role_policy with invalid policies."""
        role_name = f"role-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        # Invalid JSON
        with pytest.raises(ClientError) as e:
            aws_client.iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument="not valid json",
            )
        snapshot.match("invalid-json-error", e.value.response)

        # Invalid STS action
        invalid_action_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:InvalidAction",
                }
            ],
        }
        with pytest.raises(ClientError) as e:
            aws_client.iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(invalid_action_policy),
            )
        snapshot.match("invalid-action-error", e.value.response)

        # Policy with Resource field (not allowed in trust policies)
        policy_with_resource = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Resource": "arn:aws:s3:::example_bucket",
                }
            ],
        }
        with pytest.raises(ClientError) as e:
            aws_client.iam.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(policy_with_resource),
            )
        snapshot.match("resource-field-error", e.value.response)

    @markers.aws.validated
    def test_update_assume_role_policy(self, snapshot, aws_client, create_role):
        snapshot.add_transformer(snapshot.transform.iam_api())

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": ["ec2.amazonaws.com"]},
                    "Action": ["sts:AssumeRole"],
                }
            ],
        }

        role_name = f"role-{short_uid()}"
        result = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(policy),
        )
        snapshot.match("created_role", result)
        result = aws_client.iam.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(policy),
        )
        snapshot.match("updated_policy", result)


class TestRolePermissionsBoundary:
    @markers.aws.validated
    def test_role_permissions_boundary_lifecycle(
        self, aws_client, create_role, create_policy, snapshot
    ):
        """Test create role with PermissionsBoundary, put/delete permissions boundary."""
        role_name = f"role-{short_uid()}"
        policy_name = f"boundary-policy-{short_uid()}"

        # Create the boundary policy first
        policy_response = create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )
        snapshot.match("create-policy", policy_response)
        boundary_arn = policy_response["Policy"]["Arn"]

        # Create role with PermissionsBoundary
        create_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            PermissionsBoundary=boundary_arn,
            Description="Role with permissions boundary",
        )
        snapshot.match("create-role-with-boundary", create_response)

        # Get role - should have PermissionsBoundary
        get_role_with_boundary = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-with-boundary", get_role_with_boundary)

        # Delete permissions boundary
        aws_client.iam.delete_role_permissions_boundary(RoleName=role_name)

        # Get role - should not have PermissionsBoundary
        get_role_no_boundary = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-no-boundary", get_role_no_boundary)

        # List roles should also not show the boundary anymore
        list_roles_response = aws_client.iam.list_roles()
        roles_with_name = [r for r in list_roles_response["Roles"] if r["RoleName"] == role_name]
        snapshot.match("list-roles-without-boundary", {"Roles": roles_with_name})

        # Put permissions boundary back
        aws_client.iam.put_role_permissions_boundary(
            RoleName=role_name, PermissionsBoundary=boundary_arn
        )

        # Get role - should have PermissionsBoundary again
        get_role_boundary_restored = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-boundary-restored", get_role_boundary_restored)

        # List roles should also show the boundary
        list_roles_response = aws_client.iam.list_roles()
        roles_with_name = [r for r in list_roles_response["Roles"] if r["RoleName"] == role_name]
        snapshot.match("list-roles-with-boundary", {"Roles": roles_with_name})

    @markers.aws.validated
    def test_role_permissions_boundary_errors(
        self, aws_client, create_role, create_policy, account_id, snapshot
    ):
        """Test permissions boundary error cases."""
        role_name = f"role-{short_uid()}"
        policy_name = f"boundary-policy-{short_uid()}"

        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )
        snapshot.match("create-role", create_role_response)

        # Create a valid policy for some tests
        policy_response = create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )
        snapshot.match("create-policy", policy_response)
        valid_policy_arn = policy_response["Policy"]["Arn"]

        # Invalid boundary ARN format
        invalid_boundary_arn = f"arn:aws:iam::{account_id}:not_a_policy/invalid"
        with pytest.raises(ClientError) as e:
            aws_client.iam.put_role_permissions_boundary(
                RoleName=role_name, PermissionsBoundary=invalid_boundary_arn
            )
        snapshot.match("put-invalid-boundary-error", e.value.response)

        # Create role with invalid boundary ARN format
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_role(
                RoleName=f"role-invalid-{short_uid()}",
                AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
                PermissionsBoundary=invalid_boundary_arn,
            )
        snapshot.match("create-role-invalid-boundary-error", e.value.response)

        # Non-existent policy (valid ARN format but policy doesn't exist)
        nonexistent_policy_arn = f"arn:aws:iam::{account_id}:policy/nonexistent-policy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.put_role_permissions_boundary(
                RoleName=role_name, PermissionsBoundary=nonexistent_policy_arn
            )
        snapshot.match("put-nonexistent-policy-error", e.value.response)

        # Create role with non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_role(
                RoleName=f"role-nonexistent-{short_uid()}",
                AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
                PermissionsBoundary=nonexistent_policy_arn,
            )
        snapshot.match("create-role-nonexistent-policy-error", e.value.response)

        # Existing policy but non-existent role
        with pytest.raises(ClientError) as e:
            aws_client.iam.put_role_permissions_boundary(
                RoleName="nonexistent-role", PermissionsBoundary=valid_policy_arn
            )
        snapshot.match("put-boundary-nonexistent-role-error", e.value.response)


class TestRoleInlinePolicies:
    @markers.aws.validated
    def test_role_inline_policy_lifecycle(self, aws_client, create_role, snapshot):
        """Test put, get, list, delete inline policies on a role."""
        role_name = f"role-{short_uid()}"
        policy_name_1 = f"policy-1-{short_uid()}"
        policy_name_2 = f"policy-2-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        # Put first inline policy
        aws_client.iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name_1,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )

        # Get the policy
        get_policy_response = aws_client.iam.get_role_policy(
            RoleName=role_name, PolicyName=policy_name_1
        )
        snapshot.match("get-role-policy-1", get_policy_response)

        # List policies - should have 1
        list_response_1 = aws_client.iam.list_role_policies(RoleName=role_name)
        snapshot.match("list-role-policies-1", list_response_1)

        # Put second inline policy
        aws_client.iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name_2,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )

        # Get the second policy
        get_policy_response = aws_client.iam.get_role_policy(
            RoleName=role_name, PolicyName=policy_name_2
        )
        snapshot.match("get-role-policy-2", get_policy_response)

        # List policies - should have 2
        list_response_2 = aws_client.iam.list_role_policies(RoleName=role_name)
        snapshot.match("list-role-policies-2", list_response_2)

        # Delete first policy
        aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name_1)

        # List policies - should have 1
        list_response_3 = aws_client.iam.list_role_policies(RoleName=role_name)
        snapshot.match("list-role-policies-after-delete", list_response_3)

        # Try to get deleted policy - should fail
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name_1)
        snapshot.match("get-deleted-policy-error", e.value.response)

        # Try to delete non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name_1)
        snapshot.match("delete-nonexistent-policy-error", e.value.response)

        # Cleanup
        aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name_2)

    @markers.aws.validated
    def test_role_inline_policy_errors(self, aws_client, create_role, create_policy, snapshot):
        """Test policy attachement errors"""
        role_name = f"role-{short_uid()}"
        non_existent_role_name = "nonexistent-role"
        policy_name = "non-existent-policy"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        # Try to get non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
        snapshot.match("get-nonexistent-policy-error", e.value.response)

        # Try to delete non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        snapshot.match("delete-nonexistent-policy-error", e.value.response)

        # Try to put on non-existent role
        with pytest.raises(ClientError) as e:
            aws_client.iam.put_role_policy(
                RoleName=non_existent_role_name,
                PolicyName=policy_name,
                PolicyDocument=json.dumps(MOCK_POLICY),
            )
        snapshot.match("put-policy-nonexistent-role-error", e.value.response)

        # Try to put on non-existent role
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_role_policy(RoleName=non_existent_role_name, PolicyName=policy_name)
        snapshot.match("get-policy-nonexistent-role-error", e.value.response)

        # Try to get on non-existent role
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_role_policy(
                RoleName=non_existent_role_name, PolicyName=policy_name
            )
        snapshot.match("delete-policy-nonexistent-role-error", e.value.response)


class TestRoleManagedPolicies:
    @markers.aws.validated
    def test_role_managed_policy_lifecycle(self, aws_client, create_role, create_policy, snapshot):
        """Test attach, list, detach managed policies on a role."""
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        policy_response = create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )
        policy_arn = policy_response["Policy"]["Arn"]

        # List attached policies - should be empty
        list_response_empty = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("list-attached-policies-empty", list_response_empty)

        # Attach policy
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        # List attached policies - should have 1
        list_response_1 = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("list-attached-policies-1", list_response_1)

        # Detach policy
        aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        # List attached policies - should be empty
        list_response_after_detach = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("list-attached-policies-after-detach", list_response_after_detach)

    @markers.aws.validated
    def test_role_managed_policy_errors(self, aws_client, create_role, create_policy, snapshot):
        """Test detaching a policy that is not attached raises NoSuchEntity."""
        role_name = f"role-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        policy_response = create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # Detach a policy that is not attached
        with pytest.raises(ClientError) as e:
            aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        snapshot.match("detach-not-attached-policy-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(
                RoleName=role_name, PolicyArn="longpolicynamebutnoarn"
            )
        snapshot.match("non-existent-malformed-policy-arn", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_name)
        snapshot.match("existing-policy-name-provided", e.value.response)

        # Try to attach non-existent policy
        fake_policy_arn = policy_arn.replace(policy_name, "nonexistent-policy")
        with pytest.raises(ClientError) as e:
            aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=fake_policy_arn)
        snapshot.match("attach-nonexistent-policy-error", e.value.response)


class TestRoleTags:
    @markers.aws.validated
    def test_role_with_tags(self, aws_client, account_id, create_role, snapshot):
        """Test creating a role with tags."""
        role_name = f"role-{short_uid()}"
        path = "/role-with-tags/"
        tags = [{"Key": "test", "Value": "value"}]

        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
            Tags=tags,
            Path=path,
        )
        snapshot.match("create-role-response", create_role_response)

        get_role_response = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-response", get_role_response)

        list_role_response = aws_client.iam.list_roles(PathPrefix=path)
        snapshot.match("list-role-response", list_role_response)

    @markers.aws.validated
    def test_role_tag_operations(self, aws_client, create_role, snapshot):
        """Test tag_role, list_role_tags, untag_role operations."""
        role_name = f"role-{short_uid()}"

        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        # Get role without tags
        get_role_no_tags = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-no-tags", get_role_no_tags)

        # Add tags
        aws_client.iam.tag_role(
            RoleName=role_name,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        # Get role with tags
        get_role_with_tags = aws_client.iam.get_role(RoleName=role_name)
        snapshot.match("get-role-with-tags", get_role_with_tags)

        # List role tags
        list_tags_response = aws_client.iam.list_role_tags(RoleName=role_name)
        snapshot.match("list-role-tags", list_tags_response)

        # Update an existing tag
        aws_client.iam.tag_role(
            RoleName=role_name,
            Tags=[{"Key": "somekey", "Value": "updatedvalue"}],
        )
        list_tags_after_update = aws_client.iam.list_role_tags(RoleName=role_name)
        snapshot.match("list-role-tags-after-update", list_tags_after_update)

        # Remove one tag
        aws_client.iam.untag_role(RoleName=role_name, TagKeys=["somekey"])
        list_tags_after_untag = aws_client.iam.list_role_tags(RoleName=role_name)
        snapshot.match("list-role-tags-after-untag", list_tags_after_untag)

        # Remove remaining tag
        aws_client.iam.untag_role(RoleName=role_name, TagKeys=["someotherkey"])
        list_tags_empty = aws_client.iam.list_role_tags(RoleName=role_name)
        snapshot.match("list-role-tags-empty", list_tags_empty)

    @markers.aws.validated
    def test_role_tag_errors(self, aws_client, snapshot, create_role):
        """Test tag_role and untag_role errors for non-existent role."""
        non_existent_role_name = "test-nonexistent-role"
        role_name = f"role-{short_uid()}"

        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_role(
                RoleName=non_existent_role_name,
                Tags=[{"Key": "somekey", "Value": "somevalue"}],
            )
        snapshot.match("tag-nonexistent-role-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_role(RoleName=non_existent_role_name, TagKeys=["somekey"])
        snapshot.match("untag-nonexistent-role-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.list_role_tags(RoleName=non_existent_role_name)
        snapshot.match("list-tags-nonexistent-role-error", e.value.response)

        # test too many tags
        tags = [{"Key": str(x), "Value": str(x)} for x in range(0, 51)]
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_role(
                RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY), Tags=tags
            )
        snapshot.match("create-role-too-many-tags", e.value.response)

        create_role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )
        snapshot.match("create-role", create_role_response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_role(
                RoleName=non_existent_role_name,
                Tags=tags,
            )
        snapshot.match("tag-role-too-many-tags", e.value.response)


class TestRolePagination:
    @markers.aws.validated
    def test_list_roles_pagination(self, aws_client, create_role, snapshot):
        """Test list_roles with MaxItems, Marker, and PathPrefix."""
        path = f"/test-pagination-{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path, "<path>"))
        role_names = []

        # Create 5 roles with the same path prefix
        for i in range(5):
            role_name = f"role-{i:02d}-{short_uid()}"
            kwargs = (
                {"Description": f"Role {i}"} if i % 2 == 0 else {}
            )  # Only some roles have descriptions
            create_role_response = create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
                Path=path,
                **kwargs,
            )
            snapshot.match(f"create-role-{i}", create_role_response)
            role_names.append(role_name)

        # List with PathPrefix
        list_with_path = aws_client.iam.list_roles(PathPrefix=path)
        snapshot.match("list-roles-with-path", list_with_path)

        # List with MaxItems
        list_with_max_items = aws_client.iam.list_roles(PathPrefix=path, MaxItems=2)
        snapshot.match("list-roles-max-items", list_with_max_items)

        # List with Marker (continuation)
        marker = list_with_max_items["Marker"]
        list_with_marker = aws_client.iam.list_roles(PathPrefix=path, Marker=marker)
        snapshot.match("list-roles-with-marker", list_with_marker)

        # List with non-matching PathPrefix - empty result
        list_empty = aws_client.iam.list_roles(PathPrefix="/nonexistent-path/")
        snapshot.match("list-roles-empty", list_empty)
