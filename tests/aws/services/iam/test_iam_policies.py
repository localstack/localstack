import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

SAMPLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Statement1", "Effect": "Allow", "Action": ["iam:ListUsers"], "Resource": "*"}
    ],
}

SAMPLE_POLICY_2 = {
    "Version": "2012-10-17",
    "Statement": [
        {"Sid": "Statement1", "Effect": "Allow", "Action": ["s3:ListBucket"], "Resource": "*"}
    ],
}

SAMPLE_POLICY_3 = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Statement1",
            "Effect": "Allow",
            "Action": ["ec2:DescribeInstances"],
            "Resource": "*",
        }
    ],
}


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())


class TestPolicies:
    @markers.aws.validated
    @pytest.mark.parametrize("path", ["/test/path/", "/", None])
    def test_policy_lifecycle(self, aws_client, snapshot, path):
        """Test the lifecycle of a basic IAM policy"""
        policy_name = f"test-policy-{short_uid()}"
        kwargs = {}
        if path:
            kwargs = {"Path": path}
        response = aws_client.iam.create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY), **kwargs
        )
        snapshot.match("create-policy-response", response)
        policy_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-policy-response", response)

        response = aws_client.iam.list_policies()
        response = [
            policy for policy in response["Policies"] if policy["PolicyName"] == policy_name
        ]
        snapshot.match("filtered-policy-list", response)

        response = aws_client.iam.delete_policy(PolicyArn=policy_arn)
        snapshot.match("delete-policy-response", response)

    @markers.aws.validated
    def test_policy_errors(self, aws_client, create_policy, snapshot):
        """Tests error conditions on IAM policies"""
        policy_name = f"test-policy-{short_uid()}"
        response = create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy-response", response)

        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=policy_name, PolicyDocument=json.dumps(SAMPLE_POLICY)
            )
        snapshot.match("policy-already-exists", e.value.response)

    @markers.aws.validated
    def test_policy_version_lifecycle(self, aws_client, create_policy, snapshot):
        """Test the full CRUD lifecycle of policy versions."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Create v2 as default
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
            SetAsDefault=True,
        )
        snapshot.match("create-version-v2", response)

        # Get v2
        response = aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v2")
        snapshot.match("get-version-v2", response)

        # Delete v1 (no longer default)
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v1")

        # Create v3 as non-default
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_3),
        )
        snapshot.match("create-version-v3", response)

        # Get v3
        response = aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v3")
        snapshot.match("get-version-v3", response)

        # List all versions — should show v2 (default) and v3
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-versions", response)

    @markers.aws.validated
    def test_policy_version_set_default(self, aws_client, create_policy, snapshot):
        """Test setting the default policy version."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        # Create v2 and v3 as default
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
            SetAsDefault=True,
        )
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_3),
            SetAsDefault=True,
        )

        # List — v3 should be default
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-create", response)

        # Set v1 as default
        response = aws_client.iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v1")
        snapshot.match("set-default-v1", response)

        # List — v1 should now be default
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-set-default", response)

    @markers.aws.validated
    def test_policy_version_limit(self, aws_client, create_policy, snapshot):
        """Test the 5-version maximum for policy versions."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        # Create 4 more versions (v2–v5)
        for _ in range(4):
            aws_client.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(SAMPLE_POLICY),
            )

        # Creating a 6th version should fail
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy_version(
                PolicyArn=policy_arn,
                PolicyDocument=json.dumps(SAMPLE_POLICY),
            )
        snapshot.match("err-version-limit-exceeded", e.value.response)

        # List — should show exactly 5 versions
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-versions-at-limit", response)

        # Delete one version and verify a new one can be created
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v5")
        response = aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY),
        )
        snapshot.match("create-version-after-delete", response)

    @markers.aws.validated
    def test_policy_version_errors(
        self, aws_client, create_policy, snapshot, account_id, partition
    ):
        """Test error cases for policy version operations."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Create v2
        aws_client.iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(SAMPLE_POLICY_2),
        )

        # Error: get version from non-existent policy
        non_existent_arn = f"arn:{partition}:iam::{account_id}:policy/TestNonExistingPolicy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(PolicyArn=non_existent_arn, VersionId="v1")
        snapshot.match("err-get-version-nonexistent-policy", e.value.response)

        # Error: get non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(PolicyArn=policy_arn, VersionId="v9")
        snapshot.match("err-get-nonexistent-version", e.value.response)

        # Error: delete the default version (v1)
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v1")
        snapshot.match("err-delete-default-version", e.value.response)

        # Error: delete a non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v9")
        snapshot.match("err-delete-nonexistent-version", e.value.response)

        # Error: set default on non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(PolicyArn=non_existent_arn, VersionId="v1")
        snapshot.match("err-set-default-nonexistent-policy", e.value.response)

        # Error: set default with invalid version format
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(
                PolicyArn=policy_arn, VersionId="wrong_version_id"
            )
        snapshot.match("err-set-default-invalid-version-format", e.value.response)

        # Error: set default with non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.set_default_policy_version(PolicyArn=policy_arn, VersionId="v4")
        snapshot.match("err-set-default-nonexistent-version", e.value.response)

        # Successfully delete v2 — confirm policy still works after errors
        aws_client.iam.delete_policy_version(PolicyArn=policy_arn, VersionId="v2")

        # List — only v1 should remain
        response = aws_client.iam.list_policy_versions(PolicyArn=policy_arn)
        snapshot.match("list-after-delete", response)


class TestPolicyTags:
    @markers.aws.validated
    def test_policy_tag_lifecycle(self, aws_client, create_policy, snapshot):
        """Test creating policies with tags and verifying they appear in responses."""
        # Create policy with two tags and a description
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
            Description="testing",
        )
        snapshot.match("create-with-tags", response)
        policy_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-with-tags", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-created-tags", response)

        # Create policy with empty tag value
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[{"Key": "somekey", "Value": ""}],
        )
        snapshot.match("create-with-empty-tag-value", response)
        empty_tag_arn = response["Policy"]["Arn"]

        response = aws_client.iam.list_policy_tags(PolicyArn=empty_tag_arn)
        snapshot.match("list-empty-tag-value", response)

        # Create policy without tags
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        no_tags_arn = response["Policy"]["Arn"]

        response = aws_client.iam.get_policy(PolicyArn=no_tags_arn)
        snapshot.match("get-without-tags", response)

        # Create policy with case-sensitive tag keys (a and A are distinct)
        response = create_policy(
            PolicyDocument=json.dumps(SAMPLE_POLICY),
            Tags=[
                {"Key": "a", "Value": "lowercase"},
                {"Key": "A", "Value": "uppercase"},
            ],
        )
        snapshot.match("create-with-case-sensitive-tags", response)
        case_sensitive_arn = response["Policy"]["Arn"]

        response = aws_client.iam.list_policy_tags(PolicyArn=case_sensitive_arn)
        snapshot.match("list-case-sensitive-tags", response)

    @markers.aws.validated
    def test_policy_tag_operations(self, aws_client, create_policy, snapshot):
        """Test tag_policy, list_policy_tags (with pagination), updating tags, and untag_policy."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        snapshot.match("create-policy", response)
        policy_arn = response["Policy"]["Arn"]

        # Tag the policy
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        response = aws_client.iam.get_policy(PolicyArn=policy_arn)
        snapshot.match("get-after-tag", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-tags", response)

        # Pagination
        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn, MaxItems=1)
        snapshot.match("list-tags-page1", response)

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn, Marker=response["Marker"])
        snapshot.match("list-tags-page2", response)

        # Update existing tag value
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[{"Key": "somekey", "Value": "somenewvalue"}],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-update", response)

        # Update existing tag to empty value
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[{"Key": "somekey", "Value": ""}],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-update-empty", response)

        # Untag one key
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["somekey"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-one", response)

        # Untag remaining key
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["someotherkey"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-all", response)

        # Test case-sensitive tag operations (a and A are distinct keys)
        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "a", "Value": "lowercase"},
                {"Key": "A", "Value": "uppercase"},
            ],
        )

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-case-sensitive-tags", response)

        # Untag only lowercase 'a', uppercase 'A' should remain
        aws_client.iam.untag_policy(PolicyArn=policy_arn, TagKeys=["a"])

        response = aws_client.iam.list_policy_tags(PolicyArn=policy_arn)
        snapshot.match("list-after-untag-lowercase", response)

    @markers.aws.validated
    def test_policy_tag_create_errors(self, aws_client, snapshot):
        """Test tag validation errors on create_policy."""
        policy_doc = json.dumps(SAMPLE_POLICY)

        # Too many tags (51)
        with pytest.raises(ClientError) as e:
            too_many_tags = [{"Key": str(x), "Value": str(x)} for x in range(51)]
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=too_many_tags,
            )
        snapshot.match("err-too-many-tags", e.value.response)

        # Duplicate tag keys
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0", "Value": ""}, {"Key": "0", "Value": ""}],
            )
        snapshot.match("err-duplicate-keys", e.value.response)

        # Key too long (129 chars)
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0" * 129, "Value": ""}],
            )
        snapshot.match("err-large-key", e.value.response)

        # Value too long (257 chars)
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "0", "Value": "0" * 257}],
            )
        snapshot.match("err-large-value", e.value.response)

        # Invalid character in key
        with pytest.raises(ClientError) as e:
            aws_client.iam.create_policy(
                PolicyName=f"test-policy-{short_uid()}",
                PolicyDocument=policy_doc,
                Tags=[{"Key": "NOWAY!", "Value": ""}],
            )
        snapshot.match("err-invalid-character", e.value.response)

    @markers.aws.validated
    def test_policy_tag_update_errors(
        self, aws_client, create_policy, snapshot, account_id, partition
    ):
        """Test tag validation errors on tag_policy and untag_policy, plus non-existent policy."""
        response = create_policy(PolicyDocument=json.dumps(SAMPLE_POLICY))
        policy_arn = response["Policy"]["Arn"]

        aws_client.iam.tag_policy(
            PolicyArn=policy_arn,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        # tag_policy: too many tags (51)
        with pytest.raises(ClientError) as e:
            too_many_tags = [{"Key": str(x), "Value": str(x)} for x in range(51)]
            aws_client.iam.tag_policy(PolicyArn=policy_arn, Tags=too_many_tags)
        snapshot.match("err-tag-too-many", e.value.response)

        # tag_policy: duplicate keys
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0", "Value": ""}, {"Key": "0", "Value": ""}],
            )
        snapshot.match("err-tag-duplicate-keys", e.value.response)

        # tag_policy: key too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0" * 129, "Value": ""}],
            )
        snapshot.match("err-tag-large-key", e.value.response)

        # tag_policy: value too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "0", "Value": "0" * 257}],
            )
        snapshot.match("err-tag-large-value", e.value.response)

        # tag_policy: invalid character
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=policy_arn,
                Tags=[{"Key": "NOWAY!", "Value": ""}],
            )
        snapshot.match("err-tag-invalid-character", e.value.response)

        # tag_policy: non-existent policy
        non_existent_arn = f"arn:{partition}:iam::{account_id}:policy/NotAPolicy"
        with pytest.raises(ClientError) as e:
            aws_client.iam.tag_policy(
                PolicyArn=non_existent_arn,
                Tags=[{"Key": "some", "Value": "value"}],
            )
        snapshot.match("err-tag-nonexistent-policy", e.value.response)

        # untag_policy: too many keys (51)
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=[str(x) for x in range(51)],
            )
        snapshot.match("err-untag-too-many-keys", e.value.response)

        # untag_policy: key too long
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=["0" * 129],
            )
        snapshot.match("err-untag-large-key", e.value.response)

        # untag_policy: invalid character
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=policy_arn,
                TagKeys=["NOWAY!"],
            )
        snapshot.match("err-untag-invalid-character", e.value.response)

        # untag_policy: non-existent policy
        with pytest.raises(ClientError) as e:
            aws_client.iam.untag_policy(
                PolicyArn=non_existent_arn,
                TagKeys=["somevalue"],
            )
        snapshot.match("err-untag-nonexistent-policy", e.value.response)
