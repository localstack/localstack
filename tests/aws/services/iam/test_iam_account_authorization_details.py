import json
import logging

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

MOCK_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Action": "s3:ListBucket", "Resource": "*", "Effect": "Allow"}],
    }
)

ASSUME_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@pytest.fixture(autouse=True)
def snapshot_transformers(snapshot):
    snapshot.add_transformers_list(snapshot.transform.iam_api())


class TestGetAccountAuthorizationDetails:
    """Tests for IAM GetAccountAuthorizationDetails API with various filters."""

    @markers.aws.validated
    def test_get_account_authorization_details_filter_role(
        self,
        aws_client,
        snapshot,
        create_role,
        create_policy,
        create_instance_profile,
        account_id,
        cleanups,
    ):
        """Test GetAccountAuthorizationDetails with Role filter."""
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        instance_profile_name = f"ip-{short_uid()}"

        # Create a policy
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # Create a role with description
        role_response = create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=ASSUME_ROLE_POLICY,
            Path="/my-path/",
            Description="testing role",
        )
        snapshot.match("create-role", role_response)

        # Add inline policy to role
        aws_client.iam.put_role_policy(
            RoleName=role_name, PolicyName="inline-policy", PolicyDocument=MOCK_POLICY
        )

        # Attach managed policy to role
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

        # Add tags to role
        aws_client.iam.tag_role(
            RoleName=role_name,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        # Create instance profile and add role to it
        response = create_instance_profile(InstanceProfileName=instance_profile_name)
        snapshot.match("create-instance-profile", response)
        aws_client.iam.add_role_to_instance_profile(
            InstanceProfileName=instance_profile_name, RoleName=role_name
        )

        # Get authorization details with Role filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate(Filter=["Role"])
            .build_full_result()
        )
        # result = aws_client.iam.get_account_authorization_details(Filter=["Role"])

        # Filter to only include our test role and clear other lists
        result["RoleDetailList"] = [
            r for r in result["RoleDetailList"] if r["RoleName"] == role_name
        ]

        snapshot.match("role-filter-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_filter_user(
        self, aws_client, snapshot, create_user, create_group, create_policy, account_id
    ):
        """Test GetAccountAuthorizationDetails with User filter."""
        user_name = f"user-{short_uid()}"
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"

        # Create resources
        user_response = create_user(UserName=user_name)
        snapshot.match("create-user", user_response)
        group_response = create_group(GroupName=group_name)
        snapshot.match("create-group", group_response)
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # Add inline policy to user
        aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName="user-inline-policy", PolicyDocument=MOCK_POLICY
        )

        # Attach managed policy to user
        aws_client.iam.attach_user_policy(UserName=user_name, PolicyArn=policy_arn)

        # Add user to group
        aws_client.iam.add_user_to_group(GroupName=group_name, UserName=user_name)

        # Add tags to user
        aws_client.iam.tag_user(
            UserName=user_name,
            Tags=[
                {"Key": "somekey", "Value": "somevalue"},
                {"Key": "someotherkey", "Value": "someothervalue"},
            ],
        )

        # Get authorization details with User filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate(Filter=["User"])
            .build_full_result()
        )

        # Filter to only include our test user
        result["UserDetailList"] = [
            u for u in result["UserDetailList"] if u["UserName"] == user_name
        ]

        snapshot.match("user-filter-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_filter_group(
        self, aws_client, snapshot, create_group, create_policy, account_id
    ):
        """Test GetAccountAuthorizationDetails with Group filter."""
        group_name = f"group-{short_uid()}"
        policy_name = f"policy-{short_uid()}"

        # Create resources
        group_response = create_group(GroupName=group_name)
        snapshot.match("create-group", group_response)
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        snapshot.match("create-policy", policy_response)
        policy_arn = policy_response["Policy"]["Arn"]

        # Add inline policy to group
        aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName="group-inline-policy", PolicyDocument=MOCK_POLICY
        )

        # Attach managed policy to group
        aws_client.iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        # Get authorization details with Group filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate(Filter=["Group"])
            .build_full_result()
        )

        # Filter to only include our test group and clear other lists
        result["GroupDetailList"] = [
            g for g in result["GroupDetailList"] if g["GroupName"] == group_name
        ]

        snapshot.match("group-filter-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_filter_local_managed_policy(
        self, aws_client, snapshot, create_policy
    ):
        """Test GetAccountAuthorizationDetails with LocalManagedPolicy filter."""
        policy_name = f"policy-{short_uid()}"

        # Create a local managed policy
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        snapshot.match("create-policy", policy_response)

        # Get authorization details with LocalManagedPolicy filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate(Filter=["LocalManagedPolicy"])
            .build_full_result()
        )

        # Filter to only include our test policy and clear other lists
        result["Policies"] = [p for p in result["Policies"] if p["PolicyName"] == policy_name]

        snapshot.match("local-managed-policy-filter-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_filter_aws_managed_policy(
        self, aws_client, snapshot
    ):
        """Test GetAccountAuthorizationDetails with AWSManagedPolicy filter.

        AWS managed policies vary between accounts and over time, so we only
        verify the structure and that policies are returned, not specific content.
        """
        # Get authorization details with AWSManagedPolicy filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate(Filter=["AWSManagedPolicy"])
            .build_full_result()
        )
        result["Policies"] = [
            policy for policy in result["Policies"] if policy["PolicyName"] == "AmazonS3FullAccess"
        ]
        assert result["Policies"]
        # Match the first policy - snapshot transform so it does not matter which one, just assert the structure
        snapshot.match("aws-managed-policy-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_no_filter(
        self,
        aws_client,
        snapshot,
        create_user,
        create_group,
        create_role,
        create_policy,
    ):
        """Test GetAccountAuthorizationDetails with no filter returns all types."""
        user_name = f"user-{short_uid()}"
        group_name = f"group-{short_uid()}"
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"

        # Create resources of each type
        user_response = create_user(UserName=user_name)
        snapshot.match("create-user", user_response)
        group_response = create_group(GroupName=group_name)
        snapshot.match("create-group", group_response)
        role_response = create_role(RoleName=role_name, AssumeRolePolicyDocument=ASSUME_ROLE_POLICY)
        snapshot.match("create-role", role_response)
        policy_response = create_policy(PolicyName=policy_name, PolicyDocument=MOCK_POLICY)
        snapshot.match("create-policy", policy_response)

        # Get authorization details with no filter
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate()
            .build_full_result()
        )

        # Filter to only include our test resources
        result["UserDetailList"] = [
            u for u in result["UserDetailList"] if u["UserName"] == user_name
        ]
        result["GroupDetailList"] = [
            g for g in result["GroupDetailList"] if g["GroupName"] == group_name
        ]
        result["RoleDetailList"] = [
            r for r in result["RoleDetailList"] if r["RoleName"] == role_name
        ]
        result["Policies"] = [p for p in result["Policies"] if p["PolicyName"] == policy_name]

        snapshot.match("no-filter-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_with_inline_policies(
        self, aws_client, snapshot, create_user, create_group, create_role
    ):
        """Test that inline policies are returned correctly in authorization details."""
        user_name = f"user-{short_uid()}"
        group_name = f"group-{short_uid()}"
        role_name = f"role-{short_uid()}"

        # Create resources
        user_response = create_user(UserName=user_name)
        snapshot.match("create-user", user_response)
        group_response = create_group(GroupName=group_name)
        snapshot.match("create-group", group_response)
        role_response = create_role(RoleName=role_name, AssumeRolePolicyDocument=ASSUME_ROLE_POLICY)
        snapshot.match("create-role", role_response)

        # Add inline policies
        aws_client.iam.put_user_policy(
            UserName=user_name, PolicyName="user-inline", PolicyDocument=MOCK_POLICY
        )
        aws_client.iam.put_group_policy(
            GroupName=group_name, PolicyName="group-inline", PolicyDocument=MOCK_POLICY
        )
        aws_client.iam.put_role_policy(
            RoleName=role_name, PolicyName="role-inline", PolicyDocument=MOCK_POLICY
        )

        # Get authorization details
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate()
            .build_full_result()
        )

        # Filter to only include our test resources
        result["UserDetailList"] = [
            u for u in result["UserDetailList"] if u["UserName"] == user_name
        ]
        result["GroupDetailList"] = [
            g for g in result["GroupDetailList"] if g["GroupName"] == group_name
        ]
        result["RoleDetailList"] = [
            r for r in result["RoleDetailList"] if r["RoleName"] == role_name
        ]
        result["Policies"] = []

        snapshot.match("inline-policies-result", result)

    @markers.aws.validated
    def test_get_account_authorization_details_with_tags(
        self, aws_client, snapshot, create_user, create_role
    ):
        """Test that tags are returned correctly in authorization details."""
        user_name = f"user-{short_uid()}"
        role_name = f"role-{short_uid()}"

        # Create resources
        user_response = create_user(UserName=user_name)
        snapshot.match("create-user", user_response)
        role_response = create_role(RoleName=role_name, AssumeRolePolicyDocument=ASSUME_ROLE_POLICY)
        snapshot.match("create-role", role_response)

        # Add tags
        aws_client.iam.tag_user(
            UserName=user_name,
            Tags=[
                {"Key": "environment", "Value": "test"},
                {"Key": "team", "Value": "platform"},
            ],
        )
        aws_client.iam.tag_role(
            RoleName=role_name,
            Tags=[
                {"Key": "environment", "Value": "test"},
                {"Key": "team", "Value": "platform"},
            ],
        )

        # Get authorization details
        result = (
            aws_client.iam.get_paginator("get_account_authorization_details")
            .paginate()
            .build_full_result()
        )

        # Filter to only include our test resources
        result["UserDetailList"] = [
            u for u in result["UserDetailList"] if u["UserName"] == user_name
        ]
        result["RoleDetailList"] = [
            r for r in result["RoleDetailList"] if r["RoleName"] == role_name
        ]
        result["GroupDetailList"] = []
        result["Policies"] = []

        snapshot.match("tags-result", result)
