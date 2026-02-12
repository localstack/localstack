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

# TODO remove after new IAM implementation of managed policies
pytestmark = pytest.mark.skip


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())


class TestGetAwsManagedPolicy:
    """Tests for getting AWS-managed policies and their versions."""

    @markers.aws.validated
    def test_get_aws_managed_policy(self, aws_client, snapshot, partition):
        """Get an AWS-managed policy by ARN and verify its structure."""
        managed_policy_arn = f"arn:{partition}:iam::aws:policy/IAMUserChangePassword"
        response = aws_client.iam.get_policy(PolicyArn=managed_policy_arn)
        snapshot.match("get-policy", response)

    @markers.aws.validated
    def test_get_aws_managed_policy_version(self, aws_client, snapshot, partition):
        """Get a specific version of an AWS-managed policy, including error for non-existent version."""
        managed_policy_arn = (
            f"arn:{partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        )

        # Error: non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(
                PolicyArn=managed_policy_arn, VersionId="v2-does-not-exist"
            )
        snapshot.match("get-version-error", e.value.response)

        # Success: get v1
        response = aws_client.iam.get_policy_version(PolicyArn=managed_policy_arn, VersionId="v1")
        snapshot.match("get-version-v1", response)

    @markers.aws.validated
    def test_get_aws_managed_policy_higher_version(self, aws_client, snapshot, partition):
        """Get a higher version of an AWS-managed policy (job-function path).
        Dynamically discovers the default version to avoid hardcoding a version that drifts."""
        managed_policy_arn = f"arn:{partition}:iam::aws:policy/job-function/SystemAdministrator"

        # Error: non-existent version
        with pytest.raises(ClientError) as e:
            aws_client.iam.get_policy_version(
                PolicyArn=managed_policy_arn, VersionId="v2-does-not-exist"
            )
        snapshot.match("get-version-error", e.value.response)

        # Discover the default version dynamically
        policy = aws_client.iam.get_policy(PolicyArn=managed_policy_arn)
        snapshot.match("get-policy", policy)
        default_version_id = policy["Policy"]["DefaultVersionId"]

        # Get the default version
        response = aws_client.iam.get_policy_version(
            PolicyArn=managed_policy_arn, VersionId=default_version_id
        )
        snapshot.match("get-version-default", response)


class TestListPoliciesScope:
    """Tests for list_policies with Scope and OnlyAttached filters."""

    @markers.aws.validated
    def test_list_policies_scope_local(self, aws_client, create_policy, snapshot):
        """Verify a local policy appears in Scope=Local but not Scope=AWS."""
        policy_name = f"test-policy-{short_uid()}"
        create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )

        # Should appear in Local scope
        local_response = aws_client.iam.list_policies(Scope="Local")
        local_names = [p["PolicyName"] for p in local_response["Policies"]]
        assert policy_name in local_names

        # Should NOT appear in AWS scope
        aws_response = aws_client.iam.list_policies(Scope="AWS", MaxItems=500)
        aws_names = [p["PolicyName"] for p in aws_response["Policies"]]
        assert policy_name not in aws_names

    @markers.aws.validated
    def test_list_policies_scope_aws(self, aws_client, snapshot):
        """Verify list_policies with Scope=AWS returns AWS-managed policies with pagination."""
        response = aws_client.iam.list_policies(Scope="AWS", MaxItems=5)
        snapshot.match("list-policies-aws-page", response)

        assert response["IsTruncated"] is True
        assert len(response["Policies"]) == 5
        for policy in response["Policies"]:
            assert ":aws:policy/" in policy["Arn"]

    @markers.aws.validated
    def test_list_policies_scope_all(self, aws_client, create_policy):
        """Verify list_policies with no scope returns both local and AWS-managed policies."""
        policy_name = f"test-policy-{short_uid()}"
        create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(MOCK_POLICY),
        )

        # Paginate through all policies using boto3 paginator
        paginator = aws_client.iam.get_paginator("list_policies")
        result = paginator.paginate().build_full_result()
        all_policy_names = {p["PolicyName"] for p in result["Policies"]}

        # Our local policy should be present
        assert policy_name in all_policy_names
        # AWS-managed policies should also be present
        assert "IAMUserChangePassword" in all_policy_names

    @markers.aws.validated
    def test_list_policies_only_attached(
        self, aws_client, create_role, create_policy, snapshot, partition
    ):
        """Verify OnlyAttached filter returns only policies with attachments."""
        role_name = f"role-{short_uid()}"
        create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        )

        policy_arn_emr = f"arn:{partition}:iam::aws:policy/service-role/AmazonElasticMapReduceRole"
        policy_arn_ct = (
            f"arn:{partition}:iam::aws:policy/service-role/AWSControlTowerServiceRolePolicy"
        )

        # Attach two AWS-managed policies
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn_emr)
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn_ct)

        # Verify both appear in OnlyAttached
        attached_response = aws_client.iam.list_policies(OnlyAttached=True)
        attached_names = [p["PolicyName"] for p in attached_response["Policies"]]
        assert "AmazonElasticMapReduceRole" in attached_names
        assert "AWSControlTowerServiceRolePolicy" in attached_names
        for policy in attached_response["Policies"]:
            assert policy["AttachmentCount"] > 0

        # Verify via list_attached_role_policies
        role_policies = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("list-attached-role-policies", role_policies)

        # Detach one policy
        aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn_emr)

        # Verify the detached one is gone from OnlyAttached
        attached_response = aws_client.iam.list_policies(OnlyAttached=True)
        attached_names = [p["PolicyName"] for p in attached_response["Policies"]]
        assert "AWSControlTowerServiceRolePolicy" in attached_names
        assert "AmazonElasticMapReduceRole" not in attached_names
        for policy in attached_response["Policies"]:
            assert policy["AttachmentCount"] > 0

        # Verify via list_attached_role_policies
        role_policies_after = aws_client.iam.list_attached_role_policies(RoleName=role_name)
        snapshot.match("list-attached-role-policies-after-detach", role_policies_after)

        # Cleanup: detach remaining policy
        aws_client.iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn_ct)


class TestAttachAwsManagedPolicyToGroup:
    """Tests for attaching/detaching AWS-managed policies to/from groups."""

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
