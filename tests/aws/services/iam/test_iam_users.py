"""
Tests for IAM User operations.

Migrated from moto's test suite to LocalStack with snapshot testing for AWS parity validation.
"""

import json
import logging

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

from localstack.testing.aws.util import is_aws_cloud, wait_for_user
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)

SAMPLE_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:ListUsers",
                "Resource": "*",
            }
        ],
    }
)

# TODO remove after new IAM implementation of users
pytestmark = pytest.mark.skip


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())


class TestUserLifecycle:
    """Tests for basic user CRUD operations."""

    @markers.aws.validated
    @pytest.mark.parametrize("path", [None, "/", "/test-lifecycle-path/"])
    def test_user_lifecycle(self, aws_client, snapshot, account_id, region_name, path):
        """Test create, get, list, and delete user operations."""
        user_name = f"user-{short_uid()}"
        kwargs = {}
        if path:
            kwargs = {"Path": path}

        # Create user
        create_response = aws_client.iam.create_user(UserName=user_name, **kwargs)
        snapshot.match("create-user", create_response)

        # Get user
        get_response = aws_client.iam.get_user(UserName=user_name)
        snapshot.match("get-user", get_response)

        # List users (filtered)
        list_response = aws_client.iam.list_users()
        list_response["Users"] = [
            user for user in list_response["Users"] if user["UserName"] == user_name
        ]
        snapshot.match("list-users", list_response)

        # List users with path prefix (and partial path prefix)
        if path not in [None, "/"]:
            list_response = aws_client.iam.list_users(PathPrefix=path)
            snapshot.match("list-filtered-users", list_response)

            list_response = aws_client.iam.list_users(PathPrefix="/test-life")
            snapshot.match("list-filtered-users-partial-path", list_response)

        # List all users (verify our user is in the list)
        all_users = aws_client.iam.list_users()
        user_names = [user["UserName"] for user in all_users["Users"]]
        assert user_name in user_names

        # Delete user
        delete_response = aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user", delete_response)

        # Verify user is deleted
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_user(UserName=user_name)
        snapshot.match("get-deleted-user-error", exc.value.response)

    @markers.aws.validated
    def test_user_update(self, create_user, aws_client, snapshot):
        """Test updating user name and path."""
        original_name = f"user-{short_uid()}"
        new_name = f"user-new-{short_uid()}"
        new_path = f"/new-path-{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(new_path, "/<new-path>/"))

        create_user_response = create_user(UserName=original_name)
        snapshot.match("create-user", create_user_response)

        # Update user with new name and path
        update_response = aws_client.iam.update_user(
            UserName=original_name, NewUserName=new_name, NewPath=new_path
        )
        snapshot.match("update-user", update_response)

        # Verify new username works
        get_response = aws_client.iam.get_user(UserName=new_name)
        snapshot.match("get-updated-user", get_response)

        # Verify old username no longer exists
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_user(UserName=original_name)
        snapshot.match("get-old-user-error", exc.value.response)

        # Cleanup - delete the renamed user
        aws_client.iam.delete_user(UserName=new_name)

    @markers.aws.validated
    def test_user_errors(self, create_user, aws_client, snapshot):
        """Test error cases for user operations."""
        user_name = f"user-{short_uid()}"

        # Create user first
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Try to create duplicate user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_user(UserName=user_name)
        snapshot.match("create-duplicate-user-error", exc.value.response)

        # Try to get non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_user(UserName="nonexistent-user")
        snapshot.match("get-nonexistent-user-error", exc.value.response)

        # Try to update non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_user(UserName="nonexistent-user", NewUserName="new-name")
        snapshot.match("update-nonexistent-user-error", exc.value.response)

        # Try to delete non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_user(UserName="nonexistent-user")
        snapshot.match("delete-nonexistent-user-error", exc.value.response)

    @markers.aws.validated
    def test_delete_user_with_attached_policy(
        self, create_user, create_policy, aws_client, snapshot
    ):
        """Test that deleting a user with attached policies fails."""
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        create_user(UserName=user_name)

        # Create and attach a managed policy
        policy_response = create_policy(
            PolicyName=policy_name, PolicyDocument=SAMPLE_POLICY_DOCUMENT
        )
        policy_arn = policy_response["Policy"]["Arn"]
        aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

        # Try to delete user (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user-with-attached-policy-error", exc.value.response)

        # Detach policy and retry deletion
        aws_client.iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)

        delete_user_response = aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user-after-detach", delete_user_response)

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_user(UserName=user_name)
        snapshot.match("get-deleted-user-error", exc.value.response)

    @markers.aws.validated
    def test_delete_user_with_inline_policy(self, create_user, aws_client, snapshot):
        """Test that deleting a user with inline policies fails."""
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        create_user(UserName=user_name)

        # Add inline policy
        aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName=policy_name, PolicyDocument=SAMPLE_POLICY_DOCUMENT
        )

        # Try to delete user (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user-with-inline-policy-error", exc.value.response)

        # Delete inline policy
        aws_client.iam.delete_user_policy(UserName=user_name, PolicyName=policy_name)
        delete_user_response = aws_client.iam.delete_user(UserName=user_name)
        snapshot.match("delete-user-after-policy-delete", delete_user_response)

        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_user(UserName=user_name)
        snapshot.match("get-deleted-user-error", exc.value.response)


class TestUserLoginProfile:
    """Tests for user login profile operations."""

    @markers.aws.validated
    def test_login_profile_lifecycle(self, create_user, aws_client, snapshot):
        """Test create, get, update, and delete login profile."""
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        # Create login profile
        create_response = aws_client.iam.create_login_profile(
            UserName=user_name, Password="TestPassword123!", PasswordResetRequired=False
        )
        snapshot.match("create-login-profile", create_response)

        # Get login profile
        get_response = aws_client.iam.get_login_profile(UserName=user_name)
        snapshot.match("get-login-profile", get_response)

        # Update login profile
        aws_client.iam.update_login_profile(
            UserName=user_name, Password="NewPassword456!", PasswordResetRequired=True
        )

        # Verify update
        get_updated_response = aws_client.iam.get_login_profile(UserName=user_name)
        snapshot.match("get-updated-login-profile", get_updated_response)

        # Delete login profile
        delete_response = aws_client.iam.delete_login_profile(UserName=user_name)
        snapshot.match("delete-login-profile", delete_response)

        # Verify profile is deleted
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_login_profile(UserName=user_name)
        snapshot.match("get-deleted-login-profile-error", exc.value.response)

    @markers.aws.validated
    def test_login_profile_errors(self, create_user, aws_client, snapshot):
        """Test error cases for login profile operations."""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Try to create login profile for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_login_profile(
                UserName="nonexistent-user", Password="TestPassword123!"
            )
        snapshot.match("create-login-profile-unknown-user-error", exc.value.response)

        # Create login profile
        aws_client.iam.create_login_profile(
            UserName=user_name, Password="TestPassword123!", PasswordResetRequired=False
        )

        # Try to create duplicate login profile
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_login_profile(UserName=user_name, Password="AnotherPassword123!")
        snapshot.match("create-duplicate-login-profile-error", exc.value.response)

        # Delete login profile for cleanup
        aws_client.iam.delete_login_profile(UserName=user_name)

        # Try to delete non-existent login profile
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_login_profile(UserName=user_name)
        snapshot.match("delete-nonexistent-login-profile-error", exc.value.response)

        # Try to delete login profile for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_login_profile(UserName="nonexistent-user")
        snapshot.match("delete-login-profile-unknown-user-error", exc.value.response)


class TestUserAccessKeys:
    """Tests for user access key operations."""

    @markers.aws.validated
    def test_access_key_lifecycle(self, create_user, aws_client, snapshot):
        """Test create, list, and delete access keys."""
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        snapshot.add_transformer(snapshot.transform.key_value("SecretAccessKey"))
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        # List access keys (should be empty)
        list_empty_response = aws_client.iam.list_access_keys(UserName=user_name)
        snapshot.match("list-access-keys-empty", list_empty_response)

        # Create access key
        create_response = aws_client.iam.create_access_key(UserName=user_name)
        snapshot.match("create-access-key", create_response)
        access_key_id = create_response["AccessKey"]["AccessKeyId"]

        # Verify access key format
        assert len(access_key_id) == 20
        assert len(create_response["AccessKey"]["SecretAccessKey"]) == 40

        # List access keys
        list_response = aws_client.iam.list_access_keys(UserName=user_name)
        snapshot.match("list-access-keys", list_response)

        # Delete access key
        delete_response = aws_client.iam.delete_access_key(
            UserName=user_name, AccessKeyId=access_key_id
        )
        snapshot.match("delete-access-key", delete_response)

        # Verify key is deleted
        list_after_delete = aws_client.iam.list_access_keys(UserName=user_name)
        assert len(list_after_delete["AccessKeyMetadata"]) == 0

    @markers.aws.validated
    def test_access_key_update_status(self, create_user, aws_client, snapshot):
        """Test updating access key status."""
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        snapshot.add_transformer(snapshot.transform.key_value("SecretAccessKey"))
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        # Create access key
        create_response = aws_client.iam.create_access_key(UserName=user_name)
        access_key_id = create_response["AccessKey"]["AccessKeyId"]

        # Update to Inactive
        aws_client.iam.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Inactive"
        )
        list_inactive = aws_client.iam.list_access_keys(UserName=user_name)
        snapshot.match("list-access-keys-inactive", list_inactive)

        # Update back to Active
        aws_client.iam.update_access_key(
            UserName=user_name, AccessKeyId=access_key_id, Status="Active"
        )
        list_active = aws_client.iam.list_access_keys(UserName=user_name)
        snapshot.match("list-access-keys-active", list_active)

    @markers.aws.validated
    def test_access_key_limit(self, create_user, aws_client, snapshot):
        """Test that users are limited to 2 access keys."""
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        snapshot.add_transformer(snapshot.transform.key_value("SecretAccessKey"))
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        # Create first two access keys
        aws_client.iam.create_access_key(UserName=user_name)
        aws_client.iam.create_access_key(UserName=user_name)

        # Try to create a third (should fail)
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_access_key(UserName=user_name)
        snapshot.match("create-third-access-key-error", exc.value.response)

    @markers.aws.validated
    def test_access_key_last_used(
        self, create_user, aws_client, snapshot, aws_client_factory, region_name
    ):
        """Test get_access_key_last_used for unused key."""
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        snapshot.add_transformer(snapshot.transform.key_value("SecretAccessKey"))
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)
        aws_client.iam.put_user_policy(
            UserName=user_name,
            PolicyName=f"test-policy-{short_uid()}",
            PolicyDocument=SAMPLE_POLICY_DOCUMENT,
        )

        # Create access key
        create_response = aws_client.iam.create_access_key(UserName=user_name)
        access_key_id = create_response["AccessKey"]["AccessKeyId"]

        # Get last used for unused key
        last_used_response = aws_client.iam.get_access_key_last_used(AccessKeyId=access_key_id)
        snapshot.match("get-access-key-last-used-unused", last_used_response)

        # wait for user calls sts get caller identity
        wait_for_user(create_response["AccessKey"], region_name)
        user_clients = aws_client_factory(
            aws_access_key_id=create_response["AccessKey"]["AccessKeyId"],
            aws_secret_access_key=create_response["AccessKey"]["SecretAccessKey"],
        )
        user_clients.iam.list_users()

        def _get_last_used():
            last_used_response = aws_client.iam.get_access_key_last_used(AccessKeyId=access_key_id)
            assert last_used_response["AccessKeyLastUsed"].get("LastUsedDate")
            return last_used_response

        # this can take a long time for AWS
        last_used_response = retry(
            _get_last_used, sleep=10 if is_aws_cloud() else 1, retries=60 if is_aws_cloud() else 3
        )
        snapshot.match("get-access-key-last-used-used", last_used_response)

    @markers.aws.validated
    def test_access_key_errors(self, create_user, aws_client, snapshot):
        """Test error cases for access key operations."""
        snapshot.add_transformer(snapshot.transform.key_value("AccessKeyId"))
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        # Try to create access key for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.create_access_key(UserName="nonexistent-user")
        snapshot.match("create-access-key-unknown-user-error", exc.value.response)

        # Try to update non-existent access key
        with pytest.raises(ClientError) as exc:
            aws_client.iam.update_access_key(
                UserName=user_name, AccessKeyId="AKIAIOSFODNN7EXAMPLE", Status="Inactive"
            )
        snapshot.match("update-nonexistent-access-key-error", exc.value.response)

        # Try to get last used for non-existent key
        with pytest.raises(ClientError) as exc:
            aws_client.iam.get_access_key_last_used(AccessKeyId="AKIAIOSFODNN7EXAMPLE")
        snapshot.match("get-last-used-nonexistent-key-error", exc.value.response)

        # Try to delete access key without username - without being that user
        access_key_id = aws_client.iam.create_access_key(UserName=user_name)["AccessKey"][
            "AccessKeyId"
        ]
        with pytest.raises(ClientError) as exc:
            aws_client.iam.delete_access_key(AccessKeyId=access_key_id)
        snapshot.match("delete-access-key-without-username-error", exc.value.response)

    @markers.aws.validated
    def test_access_key_deletion_without_username(
        self, create_user, aws_client, snapshot, client_factory_for_user
    ):
        """Test delete_access_key without username specification (as that user)"""
        user_name = f"user-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)
        aws_client.iam.put_user_policy(
            UserName=user_name,
            PolicyName=f"test-policy-{short_uid()}",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "iam:DeleteAccessKey",
                            "Resource": "*",
                        }
                    ],
                }
            ),
        )

        create_response = aws_client.iam.create_access_key(UserName=user_name)
        access_key_id = create_response["AccessKey"]["AccessKeyId"]
        user_clients = client_factory_for_user(user_name=user_name)
        delete_access_key_response = user_clients.iam.delete_access_key(AccessKeyId=access_key_id)
        snapshot.match("delete-access-key", delete_access_key_response)


class TestUserPolicies:
    """Tests for user inline and managed policy operations."""

    @markers.aws.validated
    def test_user_inline_policy_lifecycle(self, create_user, aws_client, snapshot):
        """Test put, get, list, and delete inline user policies."""
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        create_user(UserName=user_name)

        # List policies (should be empty)
        list_empty = aws_client.iam.list_user_policies(UserName=user_name)
        snapshot.match("list-user-policies-empty", list_empty)

        # Put user policy
        put_response = aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName=policy_name, PolicyDocument=SAMPLE_POLICY_DOCUMENT
        )
        snapshot.match("put-user-policy", put_response)

        # Get user policy
        get_response = aws_client.iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
        snapshot.match("get-user-policy", get_response)

        # List user policies
        list_response = aws_client.iam.list_user_policies(UserName=user_name)
        snapshot.match("list-user-policies", list_response)

        # Delete user policy
        delete_response = aws_client.iam.delete_user_policy(
            UserName=user_name, PolicyName=policy_name
        )
        snapshot.match("delete-user-policy", delete_response)

        # Verify deleted
        list_after_delete = aws_client.iam.list_user_policies(UserName=user_name)
        assert len(list_after_delete["PolicyNames"]) == 0

    @markers.aws.validated
    def test_user_managed_policy_lifecycle(self, create_user, create_policy, aws_client, snapshot):
        """Test attach, list, and detach managed policies on users."""
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        create_user(UserName=user_name)

        # Create managed policy
        policy_response = create_policy(
            PolicyName=policy_name, PolicyDocument=SAMPLE_POLICY_DOCUMENT
        )
        policy_arn = policy_response["Policy"]["Arn"]

        # List attached policies (should be empty)
        list_empty = aws_client.iam.list_attached_user_policies(UserName=user_name)
        snapshot.match("list-attached-user-policies-empty", list_empty)

        # Attach policy
        attach_response = aws_client.iam.attach_user_policy(
            UserName=user_name, PolicyArn=policy_arn
        )
        snapshot.match("attach-user-policy", attach_response)

        # List attached policies
        list_response = aws_client.iam.list_attached_user_policies(UserName=user_name)
        snapshot.match("list-attached-user-policies", list_response)

        # Detach policy
        detach_response = aws_client.iam.detach_user_policy(
            UserName=user_name, PolicyArn=policy_arn
        )
        snapshot.match("detach-user-policy", detach_response)

        # Verify detached
        list_after_detach = aws_client.iam.list_attached_user_policies(UserName=user_name)
        assert len(list_after_detach["AttachedPolicies"]) == 0

    @markers.aws.validated
    def test_user_managed_policy_errors(
        self, create_user, create_policy, aws_client, snapshot, partition, account_id
    ):
        """Test error cases for managed policy operations on users."""
        user_name = f"user-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Create policy but don't attach it
        policy_response = create_policy(
            PolicyName=policy_name, PolicyDocument=SAMPLE_POLICY_DOCUMENT
        )
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # Try to attach non-existent policy
        with pytest.raises(ClientError) as exc:
            aws_client.iam.attach_user_policy(
                UserName=user_name,
                PolicyArn=f"arn:{partition}:iam::{account_id}:policy/nonexistent",
            )
        snapshot.match("attach-nonexistent-policy-error", exc.value.response)

        # Try to detach policy that was never attached
        with pytest.raises(ClientError) as exc:
            aws_client.iam.detach_user_policy(UserName=user_name, PolicyArn=policy_arn)
        snapshot.match("detach-unattached-policy-error", exc.value.response)


class TestUserTags:
    """Tests for user tagging operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..User.Tags"])
    def test_user_tag_lifecycle(self, aws_client, create_user, snapshot):
        """Test creating user with tags and listing tags."""
        user_name = f"user-{short_uid()}"
        tags = [
            {"Key": "Environment", "Value": "Test"},
            {"Key": "Team", "Value": "Platform"},
        ]

        # Create user with tags
        create_response = create_user(UserName=user_name, Tags=tags)
        snapshot.match("create-user-with-tags", create_response)

        # List user tags
        list_response = aws_client.iam.list_user_tags(UserName=user_name)
        snapshot.match("list-user-tags", list_response)

        # Get user and verify tags
        get_response = aws_client.iam.get_user(UserName=user_name)
        snapshot.match("get-user-with-tags", get_response)

    @markers.aws.validated
    def test_user_tag_operations(self, create_user, aws_client, snapshot):
        """Test tag_user and untag_user operations."""
        user_name = f"user-{short_uid()}"
        create_user(UserName=user_name)

        list_response = aws_client.iam.list_user_tags(UserName=user_name)
        snapshot.match("list-user-tags-before-tag", list_response)

        # Tag user
        tags = [
            {"Key": "key-1", "Value": "value-1"},
            {"Key": "key-2", "Value": "value-2"},
        ]
        tag_response = aws_client.iam.tag_user(UserName=user_name, Tags=tags)
        snapshot.match("tag-user", tag_response)

        # List tags
        list_response = aws_client.iam.list_user_tags(UserName=user_name)
        snapshot.match("list-user-tags-after-tag", list_response)

        # Untag user (remove one tag)
        untag_response = aws_client.iam.untag_user(UserName=user_name, TagKeys=["key-2"])
        snapshot.match("untag-user", untag_response)

        # Verify tag was removed
        list_after_untag = aws_client.iam.list_user_tags(UserName=user_name)
        snapshot.match("list-user-tags-after-untag", list_after_untag)

    @markers.aws.validated
    def test_user_tag_errors(self, aws_client, snapshot):
        """Test error cases for user tagging operations."""

        # Try to tag non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.tag_user(
                UserName="nonexistent-user", Tags=[{"Key": "key", "Value": "value"}]
            )
        snapshot.match("tag-nonexistent-user-error", exc.value.response)

        # Try to untag non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.untag_user(UserName="nonexistent-user", TagKeys=["key"])
        snapshot.match("untag-nonexistent-user-error", exc.value.response)

        # Try to list tags for non-existent user
        with pytest.raises(ClientError) as exc:
            aws_client.iam.list_user_tags(UserName="nonexistent-user")
        snapshot.match("list-tags-nonexistent-user-error", exc.value.response)


class TestUserGroups:
    """Tests for user-group membership operations."""

    @markers.aws.validated
    def test_user_group_membership(self, create_user, create_group, aws_client, snapshot):
        """Test add, list, and remove user from groups."""
        snapshot.add_transformer(SortingTransformer("Groups", lambda x: x["GroupName"]))
        user_name = f"user-{short_uid()}"
        group_name_1 = f"group-1-{short_uid()}"
        group_name_2 = f"group-2-{short_uid()}"
        create_user_response = create_user(UserName=user_name)
        snapshot.match("create-user", create_user_response)

        # Create groups
        response = create_group(GroupName=group_name_1)
        snapshot.match("create-group-1", response)
        response = create_group(GroupName=group_name_2)
        snapshot.match("create-group-2", response)

        # List groups for user (should be empty)
        list_empty = aws_client.iam.list_groups_for_user(UserName=user_name)
        snapshot.match("list-groups-for-user-empty", list_empty)

        # Add user to groups
        add_response_1 = aws_client.iam.add_user_to_group(
            GroupName=group_name_1, UserName=user_name
        )
        snapshot.match("add-user-to-group", add_response_1)

        aws_client.iam.add_user_to_group(GroupName=group_name_2, UserName=user_name)

        # List groups for user
        list_response = aws_client.iam.list_groups_for_user(UserName=user_name)
        snapshot.match("list-groups-for-user", list_response)
        assert len(list_response["Groups"]) == 2

        # Test idempotent add (adding same user again should not duplicate)
        aws_client.iam.add_user_to_group(GroupName=group_name_1, UserName=user_name)
        list_after_duplicate = aws_client.iam.list_groups_for_user(UserName=user_name)
        assert len(list_after_duplicate["Groups"]) == 2

        # Get group to see user
        get_group_response = aws_client.iam.get_group(GroupName=group_name_1)
        snapshot.match("get-group-with-user", get_group_response)

        # Remove user from group
        remove_response = aws_client.iam.remove_user_from_group(
            GroupName=group_name_1, UserName=user_name
        )
        snapshot.match("remove-user-from-group", remove_response)

        # Verify user was removed
        list_after_remove = aws_client.iam.list_groups_for_user(UserName=user_name)
        assert len(list_after_remove["Groups"]) == 1

        # Removing a user (again) who is not in the group anymore does NOT raise an error in AWS - it succeeds
        remove_response = aws_client.iam.remove_user_from_group(
            GroupName=group_name_1, UserName=user_name
        )
        snapshot.match("remove-nonmember-user-from-group", remove_response)

    @markers.aws.validated
    def test_user_group_errors(self, create_user, create_group, aws_client, snapshot):
        """Test error cases for user-group operations."""
        user_name = f"user-{short_uid()}"
        group_name = f"group-{short_uid()}"
        create_user(UserName=user_name)
        create_group(GroupName=group_name)

        # Try to add non-existent user to group
        with pytest.raises(ClientError) as exc:
            aws_client.iam.add_user_to_group(GroupName=group_name, UserName="nonexistent-user")
        snapshot.match("add-nonexistent-user-to-group-error", exc.value.response)

        # Try to add user to non-existent group
        with pytest.raises(ClientError) as exc:
            aws_client.iam.add_user_to_group(GroupName="nonexistent-group", UserName=user_name)
        snapshot.match("add-user-to-nonexistent-group-error", exc.value.response)

        # Try to remove user from non-existent group
        with pytest.raises(ClientError) as exc:
            aws_client.iam.remove_user_from_group(GroupName="nonexistent-group", UserName=user_name)
        snapshot.match("remove-user-from-nonexistent-group-error", exc.value.response)
