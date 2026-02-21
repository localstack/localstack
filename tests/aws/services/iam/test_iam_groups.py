"""
Tests for IAM Group operations.

Migrated from moto: tests/test_iam/test_iam_groups.py and tests/test_iam/test_iam.py
"""

import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid

MOCK_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Action": "s3:ListBucket",
            "Resource": ["arn:aws:s3:::example_bucket"],
        },
    }
)


class TestIAMGroupsCRUD:
    """Tests for IAM Group create, get, list, delete, and update operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_create_group(self, create_group, aws_client, snapshot):
        """Test creating a group and duplicate detection."""
        group_name = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        response = create_group(GroupName=group_name)
        snapshot.match("create-group", response)

        with pytest.raises(ClientError) as ex:
            aws_client.iam.create_group(GroupName=group_name)
        snapshot.match("create-group-duplicate", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_get_group(self, create_group, aws_client, snapshot, account_id, region_name):
        """Test getting group details and error handling for non-existent groups."""
        group_name = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        created = create_group(GroupName=group_name)["Group"]
        snapshot.match("created-group", created)

        retrieved = aws_client.iam.get_group(GroupName=group_name)["Group"]
        snapshot.match("get-group", retrieved)

        with pytest.raises(ClientError) as ex:
            aws_client.iam.get_group(GroupName="non-existent-group")
        snapshot.match("get-group-not-found", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_get_group_with_path(self, create_group, aws_client, snapshot):
        """Test getting groups with different paths."""
        group_name = f"group-{short_uid()}"
        other_group_name = f"group-{short_uid()}"
        path = "/some/location/"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        create_group(GroupName=group_name)
        result = aws_client.iam.get_group(GroupName=group_name)
        snapshot.match("get-group-default-path", result)

        other_group = create_group(GroupName=other_group_name, Path=path)
        snapshot.match("create-group-with-path", other_group)

    @markers.aws.validated
    def test_list_groups(self, create_group, aws_client, snapshot):
        """Test listing all groups."""
        group_name_1 = f"group-{short_uid()}"
        group_name_2 = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        create_group(GroupName=group_name_1)
        create_group(GroupName=group_name_2)

        groups = aws_client.iam.list_groups()["Groups"]
        created_groups = [g for g in groups if g["GroupName"] in [group_name_1, group_name_2]]
        snapshot.match("list-groups", created_groups)

    @markers.aws.validated
    def test_delete_group(self, aws_client, snapshot):
        """Test deleting a group."""
        group_name = f"group-{short_uid()}"

        aws_client.iam.create_group(GroupName=group_name)
        groups = aws_client.iam.list_groups()["Groups"]
        assert any(g["GroupName"] == group_name for g in groups)

        delete_response = aws_client.iam.delete_group(GroupName=group_name)
        snapshot.match("delete-response", delete_response)

        groups = aws_client.iam.list_groups()["Groups"]
        assert not any(g["GroupName"] == group_name for g in groups)

    @markers.aws.validated
    def test_delete_unknown_group(self, aws_client, snapshot):
        """Test error handling when deleting non-existent group."""
        snapshot.add_transformer(snapshot.transform.iam_api())

        with pytest.raises(ClientError) as ex:
            aws_client.iam.delete_group(GroupName="unknown-group")
        snapshot.match("delete-unknown-group", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message", "$..Arn", "$..Path"])
    def test_update_group_name(self, aws_client, snapshot, cleanups):
        """Test updating group name."""
        group_name = f"group-{short_uid()}"
        new_group_name = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        aws_client.iam.create_group(GroupName=group_name)
        initial_group = aws_client.iam.get_group(GroupName=group_name)["Group"]
        snapshot.match("original_group", initial_group)

        aws_client.iam.update_group(GroupName=group_name, NewGroupName=new_group_name)
        cleanups.append(lambda: aws_client.iam.delete_group(GroupName=new_group_name))

        with pytest.raises(ClientError) as ex:
            aws_client.iam.get_group(GroupName=group_name)
        snapshot.match("old-group-not-found", ex.value.response)

        result = aws_client.iam.get_group(GroupName=new_group_name)["Group"]
        snapshot.match("updated-group", result)

    @markers.aws.validated
    def test_update_group_path(self, create_group, aws_client, snapshot, cleanups):
        """Test updating group path."""
        group_name = f"group-{short_uid()}"
        new_group_name = f"group-{short_uid()}"
        original_path = "/path/"
        new_path = "/new-path/"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        aws_client.iam.create_group(GroupName=group_name, Path=original_path)
        aws_client.iam.update_group(
            GroupName=group_name, NewGroupName=new_group_name, NewPath=new_path
        )
        cleanups.append(lambda: aws_client.iam.delete_group(GroupName=new_group_name))

        new_group = aws_client.iam.get_group(GroupName=new_group_name)["Group"]
        snapshot.match("updated-group-with-new-path", new_group)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Error.message", "$..Error.Type", "$..ResponseMetadata.HTTPStatusCode"]
    )
    def test_update_group_not_found(self, aws_client, snapshot):
        """Test error handling when updating non-existent group."""
        snapshot.add_transformer(snapshot.transform.iam_api())

        with pytest.raises(ClientError) as ex:
            aws_client.iam.update_group(GroupName="nonexisting", NewGroupName="new-name")
        snapshot.match("update-nonexistent-group", ex.value.response)

    @markers.aws.validated
    def test_update_group_duplicate_name(self, create_group, aws_client, snapshot):
        """Test error handling when updating to existing group name."""
        group_name_1 = f"group-{short_uid()}"
        group_name_2 = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.regex(group_name_2, "<group-name-2>"))

        create_group(GroupName=group_name_1)
        create_group(GroupName=group_name_2)

        with pytest.raises(ClientError) as ex:
            aws_client.iam.update_group(GroupName=group_name_1, NewGroupName=group_name_2)
        snapshot.match("update-duplicate-name", ex.value.response)


class TestIAMGroupsMembership:
    """Tests for IAM Group user membership operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_add_user_to_group(self, create_group, create_user, aws_client, snapshot):
        """Test adding user to group."""
        group_name = f"group-{short_uid()}"
        user_name = f"user-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("UserName"))

        create_group(GroupName=group_name)
        create_user(UserName=user_name)
        aws_client.iam.add_user_to_group(GroupName=group_name, UserName=user_name)

        result = aws_client.iam.get_group(GroupName=group_name)
        snapshot.match("group-with-user", result)

    @markers.aws.validated
    def test_add_unknown_user_to_group(self, create_group, aws_client, snapshot):
        """Test error when adding non-existent user to group."""
        group_name = f"group-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))

        create_group(GroupName=group_name)

        with pytest.raises(ClientError) as ex:
            aws_client.iam.add_user_to_group(GroupName=group_name, UserName="non-existent-user")
        snapshot.match("add-unknown-user", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_add_user_to_unknown_group(self, create_user, aws_client, snapshot):
        """Test error when adding user to non-existent group."""
        user_name = f"user-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.regex(user_name, "<user-name>"))

        create_user(UserName=user_name)

        with pytest.raises(ClientError) as ex:
            aws_client.iam.add_user_to_group(GroupName="non-existent-group", UserName=user_name)
        snapshot.match("add-user-unknown-group", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_remove_user_from_group(self, create_group, create_user, aws_client, snapshot):
        """Test removing user from group."""
        group_name = f"group-{short_uid()}"
        user_name = f"user-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("UserName"))

        create_group(GroupName=group_name)
        create_user(UserName=user_name)
        aws_client.iam.add_user_to_group(GroupName=group_name, UserName=user_name)

        result_before = aws_client.iam.get_group(GroupName=group_name)
        snapshot.match("group-before-remove", result_before)

        aws_client.iam.remove_user_from_group(GroupName=group_name, UserName=user_name)

        result_after = aws_client.iam.get_group(GroupName=group_name)
        snapshot.match("group-after-remove", result_after)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_remove_user_from_unknown_group(self, aws_client, snapshot):
        """Test error when removing user from non-existent group."""
        snapshot.add_transformer(snapshot.transform.iam_api())

        with pytest.raises(ClientError) as ex:
            aws_client.iam.remove_user_from_group(
                GroupName="non-existent-group", UserName="any-user"
            )
        snapshot.match("remove-from-unknown-group", ex.value.response)

    @markers.aws.validated
    def test_add_user_to_group_idempotent(self, create_group, create_user, aws_client, snapshot):
        """Test that adding user to group is idempotent."""
        group_name = f"group-{short_uid()}"
        user_name = f"user-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("UserName"))

        create_group(GroupName=group_name)
        create_user(UserName=user_name)

        # Add the same user twice
        aws_client.iam.add_user_to_group(GroupName=group_name, UserName=user_name)
        aws_client.iam.add_user_to_group(GroupName=group_name, UserName=user_name)

        groups = aws_client.iam.list_groups_for_user(UserName=user_name)["Groups"]
        snapshot.match("groups-before-remove", groups)

        # Remove once should leave none
        aws_client.iam.remove_user_from_group(GroupName=group_name, UserName=user_name)

        groups = aws_client.iam.list_groups_for_user(UserName=user_name)["Groups"]
        snapshot.match("groups-after-remove", groups)

    @markers.aws.validated
    def test_list_groups_for_user(self, create_group, create_user, aws_client, snapshot):
        """Test listing groups for a user."""
        group_name_1 = f"group-{short_uid()}"
        group_name_2 = f"group-{short_uid()}"
        group_name_3 = f"group-{short_uid()}"
        user_name = f"user-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("UserName"))

        create_group(GroupName=group_name_1)
        create_group(GroupName=group_name_2)
        create_group(GroupName=group_name_3)  # User not added to this one
        create_user(UserName=user_name)

        aws_client.iam.add_user_to_group(GroupName=group_name_1, UserName=user_name)
        aws_client.iam.add_user_to_group(GroupName=group_name_2, UserName=user_name)

        groups = aws_client.iam.list_groups_for_user(UserName=user_name)["Groups"]
        snapshot.match("list-groups-for-user", groups)


class TestIAMGroupsPolicies:
    """Tests for IAM Group inline and managed policy operations."""

    @markers.aws.validated
    def test_put_group_policy(self, create_group, aws_client, snapshot):
        """Test adding inline policy to group."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("PolicyName"))

        create_group(GroupName=group_name)
        response = aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName=policy_name, PolicyDocument=MOCK_POLICY
        )
        snapshot.match("put-group-policy", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_get_group_policy(self, create_group, aws_client, snapshot):
        """Test getting inline policy from group."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("PolicyName"))

        create_group(GroupName=group_name)

        # Test error when policy doesn't exist
        with pytest.raises(ClientError) as ex:
            aws_client.iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
        snapshot.match("get-nonexistent-policy", ex.value.response)

        # Add policy and retrieve it
        aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName=policy_name, PolicyDocument=MOCK_POLICY
        )
        policy = aws_client.iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
        snapshot.match("get-group-policy", policy)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..IsTruncated"])
    def test_list_group_policies(self, create_group, aws_client, snapshot):
        """Test listing inline policies for group."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.regex(policy_name, "<policy-name>"))

        create_group(GroupName=group_name)

        policies = aws_client.iam.list_group_policies(GroupName=group_name)
        snapshot.match("list-empty-policies", policies)

        aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName=policy_name, PolicyDocument=MOCK_POLICY
        )

        policies = aws_client.iam.list_group_policies(GroupName=group_name)
        snapshot.match("list-policies-with-one", policies)

    @markers.aws.validated
    def test_attach_detach_group_policy(self, create_group, create_policy, aws_client, snapshot):
        """Test attaching and detaching managed policies to/from group."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.regex(policy_name, "<policy-name>"))

        create_group(GroupName=group_name)
        policy_arn = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)["Policy"][
            "Arn"
        ]

        # Initially no policies attached
        attached = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("no-attached-policies", attached)
        assert attached["AttachedPolicies"] == []

        # Attach policy
        aws_client.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        attached = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("one-attached-policy", attached)

        # Detach policy
        aws_client.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        attached = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("after-detach", attached)

    @markers.aws.validated
    def test_detach_unattached_group_policy(
        self, create_group, create_policy, aws_client, snapshot
    ):
        """Test error when detaching policy that is not attached."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.iam_api())
        snapshot.add_transformer(snapshot.transform.key_value("GroupName"))
        snapshot.add_transformer(snapshot.transform.regex(policy_name, "<policy-name>"))

        create_group(GroupName=group_name)
        policy_arn = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)["Policy"][
            "Arn"
        ]

        attached = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        assert len(attached["AttachedPolicies"]) == 0

        with pytest.raises(ClientError) as ex:
            aws_client.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        snapshot.match("detach-unattached-error", ex.value.response)

    @markers.aws.validated
    def test_attach_detach_aws_managed_policy_group(
        self, aws_client, create_group, snapshot, partition
    ):
        """Attach and detach an AWS-managed policy to a group."""
        group_name = f"group-{short_uid()}"
        create_group(GroupName=group_name)

        policy_arn = (
            f"arn:{partition}:iam::aws:policy/service-role/AmazonElasticMapReduceforEC2Role"
        )

        # Verify empty attached list
        response = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("list-attached-empty", response)

        # Attach policy
        aws_client.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        # Verify attached
        response = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("list-attached-after-attach", response)

        # Detach policy
        aws_client.iam.detach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        # Verify empty again
        response = aws_client.iam.list_attached_group_policies(GroupName=group_name)
        snapshot.match("list-attached-after-detach", response)
