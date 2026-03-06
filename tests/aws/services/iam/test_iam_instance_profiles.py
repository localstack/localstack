"""Tests for IAM Instance Profile operations."""

import json

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import SortingTransformer

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


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformer(snapshot.transform.iam_api())


class TestInstanceProfileLifecycle:
    @markers.aws.validated
    def test_instance_profile_lifecycle(self, aws_client, create_instance_profile, snapshot):
        """Test basic instance profile lifecycle: create, get, delete."""
        profile_name = f"profile-{short_uid()}"
        profile_name_default = f"profile-default-{short_uid()}"
        path_prefix = f"/test-path-{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path_prefix, "/<path-prefix>/"))

        # Create instance profile with path
        create_response = create_instance_profile(
            InstanceProfileName=profile_name, Path=path_prefix
        )
        snapshot.match("create-instance-profile", create_response)

        # Get instance profile
        get_response = aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-instance-profile", get_response)

        # Create another profile with default path
        create_default_response = create_instance_profile(InstanceProfileName=profile_name_default)
        snapshot.match("create-instance-profile-default-path", create_default_response)

        # Delete and verify deletion
        aws_client.iam.delete_instance_profile(InstanceProfileName=profile_name)

        with pytest.raises(ClientError) as e:
            aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-deleted-error", e.value.response)

    @markers.aws.validated
    def test_instance_profile_errors(self, aws_client, create_instance_profile, snapshot):
        """Test instance profile errors: NoSuchEntity and EntityAlreadyExists."""
        nonexistent_name = "nonexistent-profile"

        # Get non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_instance_profile(InstanceProfileName=nonexistent_name)
        snapshot.match("get-nonexistent-error", e.value.response)

        # Create duplicate profile - capture response to register the name for transformation
        profile_name = f"profile-{short_uid()}"
        create_response = create_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("create-profile-for-duplicate-test", create_response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.create_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("create-duplicate-error", e.value.response)

        # Delete non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_instance_profile(InstanceProfileName=nonexistent_name)
        snapshot.match("delete-nonexistent-error", e.value.response)

    @markers.aws.validated
    def test_list_instance_profiles(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test listing instance profiles."""
        snapshot.add_transformer(
            SortingTransformer("InstanceProfiles", lambda p: p["InstanceProfileName"])
        )

        profile_name_1 = f"profile-1-{short_uid()}"
        profile_name_2 = f"profile-2-{short_uid()}"

        # Create profiles with same path
        create_instance_profile(InstanceProfileName=profile_name_1)
        create_instance_profile(InstanceProfileName=profile_name_2)

        # Create a role and add to one profile
        role_name = f"role-{short_uid()}"
        create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name_1, RoleName=role_name
        )

        # List all profiles with path prefix - filter to test profiles only
        list_response = aws_client.iam.list_instance_profiles()
        list_response["InstanceProfiles"] = [
            instance_profile
            for instance_profile in list_response["InstanceProfiles"]
            if instance_profile["InstanceProfileName"] in {profile_name_1, profile_name_2}
        ]
        snapshot.match("list-instance-profiles", list_response)

    @markers.aws.validated
    def test_list_instance_profiles_path_prefix(
        self, aws_client, create_instance_profile, snapshot
    ):
        """Test listing instance profiles with path prefix filtering."""
        path_prefix_1 = f"/path-a-{short_uid()}/"
        path_prefix_2 = f"/path-b-{short_uid()}/"
        snapshot.add_transformer(snapshot.transform.regex(path_prefix_1, "/<path-prefix-1>/"))
        snapshot.add_transformer(snapshot.transform.regex(path_prefix_2, "/<path-prefix-2>/"))

        profile_name_1 = f"profile-a-{short_uid()}"
        profile_name_2 = f"profile-b-{short_uid()}"

        # Create profiles with different paths
        create_instance_profile(InstanceProfileName=profile_name_1, Path=path_prefix_1)
        create_instance_profile(InstanceProfileName=profile_name_2, Path=path_prefix_2)

        # List with specific path prefix
        list_with_prefix = aws_client.iam.list_instance_profiles(PathPrefix=path_prefix_1)
        snapshot.match("list-with-prefix", list_with_prefix)

        # List with non-matching path prefix
        list_empty = aws_client.iam.list_instance_profiles(PathPrefix="/nonexistent-path/")
        snapshot.match("list-empty-prefix", list_empty)


class TestInstanceProfileRoles:
    @markers.aws.validated
    def test_add_remove_role_from_instance_profile(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test adding and removing a role from an instance profile."""
        profile_name = f"profile-{short_uid()}"
        role_name = f"role-{short_uid()}"

        # Create profile
        create_profile_response = create_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("create-profile", create_profile_response)

        # Create role
        create_role_response = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY)
        )
        snapshot.match("create-role", create_role_response)

        # Add role to profile
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )

        # Get profile with role
        get_with_role = aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-with-role", get_with_role)

        # Remove role from profile
        aws_client.iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )

        # Get profile without role
        get_without_role = aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-without-role", get_without_role)

    @markers.aws.validated
    def test_add_second_role_to_instance_profile_error(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test that adding a second role to an instance profile fails with LimitExceeded."""
        profile_name = f"profile-{short_uid()}"
        role_name_1 = f"role-1-{short_uid()}"
        role_name_2 = f"role-2-{short_uid()}"

        # Create profile and two roles
        create_instance_profile(InstanceProfileName=profile_name)
        create_role(RoleName=role_name_1, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
        create_role(RoleName=role_name_2, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))

        # Add first role
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name_1
        )

        # Try to add second role - should fail with LimitExceeded
        with pytest.raises(ClientError) as e:
            aws_client.iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name_2
            )
        snapshot.match("add-second-role-error", e.value.response)

    @markers.aws.validated
    def test_delete_instance_profile_with_role_error(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test that deleting an instance profile with an attached role fails with DeleteConflict."""
        profile_name = f"profile-{short_uid()}"
        role_name = f"role-{short_uid()}"

        # Create profile and role - capture responses to register names for transformation
        create_profile_response = create_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("create-profile", create_profile_response)
        create_role_response = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY)
        )
        snapshot.match("create-role", create_role_response)

        # Add role to profile
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )

        # Try to delete profile with role - should fail with DeleteConflict
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("delete-with-role-error", e.value.response)

        # Remove role and delete profile
        aws_client.iam.remove_role_from_instance_profile(
            InstanceProfileName=profile_name, RoleName=role_name
        )
        aws_client.iam.delete_instance_profile(InstanceProfileName=profile_name)

        # Verify deletion
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-deleted-error", e.value.response)

    @markers.aws.validated
    def test_role_instance_profile_operations_errors(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test add/remove role operations with non-existent profile/role."""
        profile_name = f"profile-{short_uid()}"
        role_name = f"role-{short_uid()}"
        nonexistent_profile = "nonexistent-profile"
        nonexistent_role = "nonexistent-role"

        # Create actual profile and role - capture responses to register names for transformation
        create_profile_response = create_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("create-profile", create_profile_response)
        create_role_response = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY)
        )
        snapshot.match("create-role", create_role_response)

        # Add role to non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.add_role_to_instance_profile(
                InstanceProfileName=nonexistent_profile, RoleName=role_name
            )
        snapshot.match("add-role-nonexistent-profile-error", e.value.response)

        # Add non-existent role to profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.add_role_to_instance_profile(
                InstanceProfileName=profile_name, RoleName=nonexistent_role
            )
        snapshot.match("add-nonexistent-role-error", e.value.response)

        # Remove role from non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.remove_role_from_instance_profile(
                InstanceProfileName=nonexistent_profile, RoleName=role_name
            )
        snapshot.match("remove-role-nonexistent-profile-error", e.value.response)

        # Remove non-existent role from profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=nonexistent_role
            )
        snapshot.match("remove-nonexistent-role-error", e.value.response)

        # Remove role that is not attached to profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name, RoleName=role_name
            )
        snapshot.match("remove-unattached-role-error", e.value.response)

        # List instance profiles for non-existent role
        with pytest.raises(ClientError) as e:
            aws_client.iam.list_instance_profiles_for_role(RoleName=nonexistent_role)
        snapshot.match("list-profiles-nonexistent-role-error", e.value.response)

    @markers.aws.validated
    def test_list_instance_profiles_for_role(
        self, aws_client, create_instance_profile, create_role, snapshot
    ):
        """Test listing instance profiles for a specific role."""
        snapshot.add_transformer(
            SortingTransformer("InstanceProfiles", lambda p: p["InstanceProfileName"])
        )

        profile_name_1 = f"profile-role-1-{short_uid()}"
        profile_name_2 = f"profile-role-2-{short_uid()}"
        role_name = f"role-{short_uid()}"
        role_name_2 = f"role-2-{short_uid()}"

        # Create roles
        create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
        create_role(RoleName=role_name_2, AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))

        # Create profiles
        create_instance_profile(InstanceProfileName=profile_name_1)
        create_instance_profile(InstanceProfileName=profile_name_2)

        # Add role to both profiles
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name_1, RoleName=role_name
        )
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name_2, RoleName=role_name
        )

        # List for role with profiles
        list_response = aws_client.iam.list_instance_profiles_for_role(RoleName=role_name)
        snapshot.match("list-for-role", list_response)

        # List for role with no profiles
        list_empty = aws_client.iam.list_instance_profiles_for_role(RoleName=role_name_2)
        snapshot.match("list-for-role-empty", list_empty)


class TestInstanceProfileTags:
    @markers.aws.validated
    def test_instance_profile_tag_lifecycle(self, aws_client, create_instance_profile, snapshot):
        """Test tag, list tags, untag operations on instance profile."""
        profile_name = f"profile-{short_uid()}"
        snapshot.add_transformer(SortingTransformer("Tags", lambda t: t["Key"]))

        # Create profile
        create_instance_profile(InstanceProfileName=profile_name)

        # List tags - empty
        list_tags_empty = aws_client.iam.list_instance_profile_tags(
            InstanceProfileName=profile_name
        )
        snapshot.match("list-tags-empty", list_tags_empty)

        # Tag the profile
        aws_client.iam.tag_instance_profile(
            InstanceProfileName=profile_name,
            Tags=[{"Key": "MyKey", "Value": "myValue"}],
        )

        # List tags after tagging
        list_tags = aws_client.iam.list_instance_profile_tags(InstanceProfileName=profile_name)
        snapshot.match("list-tags-after-tag", list_tags)

        # Get profile with tags
        get_with_tags = aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-with-tags", get_with_tags)

        # Add another tag
        aws_client.iam.tag_instance_profile(
            InstanceProfileName=profile_name,
            Tags=[{"Key": "MyKey2", "Value": "myValue2"}],
        )

        # List tags after adding another
        list_tags_2 = aws_client.iam.list_instance_profile_tags(InstanceProfileName=profile_name)
        # Sort tags for consistent snapshot
        snapshot.match("list-tags-two-tags", list_tags_2)

        # Untag one key
        aws_client.iam.untag_instance_profile(InstanceProfileName=profile_name, TagKeys=["MyKey"])

        # List tags after untag
        list_after_untag = aws_client.iam.list_instance_profile_tags(
            InstanceProfileName=profile_name
        )
        snapshot.match("list-after-untag", list_after_untag)

        # Untag remaining key
        aws_client.iam.untag_instance_profile(InstanceProfileName=profile_name, TagKeys=["MyKey2"])

        # List tags - empty again
        list_tags_final = aws_client.iam.list_instance_profile_tags(
            InstanceProfileName=profile_name
        )
        snapshot.match("list-tags-final-empty", list_tags_final)

    @markers.aws.validated
    def test_instance_profile_create_with_tags(self, aws_client, create_instance_profile, snapshot):
        """Test creating instance profile with tags."""
        profile_name = f"profile-{short_uid()}"

        # Create profile with tags
        create_response = create_instance_profile(
            InstanceProfileName=profile_name,
            Tags=[{"Key": "InitialKey", "Value": "InitialValue"}],
        )
        snapshot.match("create-with-tags", create_response)

        # Get profile - should have tags
        get_response = aws_client.iam.get_instance_profile(InstanceProfileName=profile_name)
        snapshot.match("get-with-initial-tags", get_response)

    @markers.aws.validated
    def test_instance_profile_tag_errors(self, aws_client, create_instance_profile, snapshot):
        """Test tag/untag/list tags errors for non-existent instance profile."""
        nonexistent_name = "nonexistent-profile"

        # Tag non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_instance_profile(
                InstanceProfileName=nonexistent_name,
                Tags=[{"Key": "Key", "Value": "Value"}],
            )
        snapshot.match("tag-nonexistent-error", e.value.response)

        # Untag non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_instance_profile(
                InstanceProfileName=nonexistent_name, TagKeys=["Key"]
            )
        snapshot.match("untag-nonexistent-error", e.value.response)

        # List tags for non-existent profile
        with pytest.raises(ClientError) as e:
            aws_client.iam.list_instance_profile_tags(InstanceProfileName=nonexistent_name)
        snapshot.match("list-tags-nonexistent-error", e.value.response)
