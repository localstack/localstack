"""Tests for CloudWatch Logs - Resource Policy operations."""

import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid

# Maximum number of resource policies per region (AWS limit)
MAX_RESOURCE_POLICIES_PER_REGION = 10

JSON_POLICY_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Route53LogsToCloudWatchLogs",
                "Effect": "Allow",
                "Principal": {"Service": ["route53.amazonaws.com"]},
                "Action": "logs:PutLogEvents",
                "Resource": "log_arn",
            }
        ],
    }
)


class TestResourcePolicies:
    """Tests for resource policy operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..policyScope"])
    def test_put_resource_policy(self, aws_client, snapshot, cleanups):
        """Test creating a resource policy."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-log-group-{short_uid()}"
        policy_name = f"test-policy-{short_uid()}"

        # Create a log group to use its ARN in the policy
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        log_group_info = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        log_group_arn = log_group_info["logGroups"][0]["arn"]

        policy_doc = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "Route53LogsToCloudWatchLogs",
                        "Effect": "Allow",
                        "Principal": {"Service": ["route53.amazonaws.com"]},
                        "Action": "logs:PutLogEvents",
                        "Resource": log_group_arn,
                    }
                ],
            }
        )

        response = aws_client.logs.put_resource_policy(
            policyName=policy_name, policyDocument=policy_doc
        )
        cleanups.append(lambda: aws_client.logs.delete_resource_policy(policyName=policy_name))

        snapshot.add_transformer(snapshot.transform.key_value("policyName"))
        snapshot.add_transformer(
            snapshot.transform.key_value("lastUpdatedTime", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.regex(log_group_arn, "<log-group-arn>"))
        snapshot.match("put-resource-policy", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..policyDocument.Statement..Principal.Service",
            "$..policyDocument.Version",
            "$..policyScope",
        ]
    )
    def test_put_resource_policy_update(self, aws_client, snapshot, cleanups):
        """Test updating an existing resource policy."""
        policy_name = f"test-policy-{short_uid()}"

        # Create initial policy
        aws_client.logs.put_resource_policy(policyName=policy_name, policyDocument=JSON_POLICY_DOC)
        cleanups.append(lambda: aws_client.logs.delete_resource_policy(policyName=policy_name))

        response = aws_client.logs.describe_resource_policies()
        policies = [p for p in response["resourcePolicies"] if p["policyName"] == policy_name]
        assert len(policies) == 1
        created_time = policies[0]["lastUpdatedTime"]

        # Update the policy with different document
        new_document = '{"Statement":[{"Action":"logs:*","Effect":"Allow","Principal":{"Service": ["route53.amazonaws.com"]},"Resource":"*"}]}'
        aws_client.logs.put_resource_policy(policyName=policy_name, policyDocument=new_document)
        response = aws_client.logs.describe_resource_policies()
        policies = [p for p in response["resourcePolicies"] if p["policyName"] == policy_name]

        assert created_time != policies[0]["lastUpdatedTime"]

        snapshot.add_transformer(snapshot.transform.key_value("policyName"))
        snapshot.add_transformer(
            snapshot.transform.key_value("lastUpdatedTime", reference_replacement=False)
        )
        snapshot.match("updated-policy", policies[0])

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..policyDocument.Statement..Principal.Service",
            "$..policyDocument.Version",
            "$..policyScope",
        ]
    )
    def test_describe_resource_policies(self, aws_client, snapshot, cleanups):
        """Test describing resource policies."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        prefix = f"test-policy-{short_uid()}"

        # Create multiple policies
        for i in range(3):
            policy_name = f"{prefix}-{i}"
            aws_client.logs.put_resource_policy(
                policyName=policy_name, policyDocument=JSON_POLICY_DOC
            )
            cleanups.append(
                lambda pn=policy_name: aws_client.logs.delete_resource_policy(policyName=pn)
            )

        response = aws_client.logs.describe_resource_policies()
        snapshot.match("describe-resource-policies", response)

        # Should contain at least the 3 we created
        policies = [p for p in response["resourcePolicies"] if p["policyName"].startswith(prefix)]
        snapshot.add_transformer(snapshot.transform.key_value("policyName"))
        snapshot.add_transformer(
            snapshot.transform.key_value("lastUpdatedTime", reference_replacement=False)
        )
        snapshot.match("policies", policies)

    @markers.aws.validated
    def test_delete_resource_policy(self, aws_client, cleanups):
        """Test deleting a resource policy."""
        policy_name = f"test-policy-{short_uid()}"

        aws_client.logs.put_resource_policy(policyName=policy_name, policyDocument=JSON_POLICY_DOC)

        # Verify it exists
        response = aws_client.logs.describe_resource_policies()
        policy_names = [p["policyName"] for p in response["resourcePolicies"]]
        assert policy_name in policy_names

        # Delete the policy
        aws_client.logs.delete_resource_policy(policyName=policy_name)

        # Verify it's deleted
        response = aws_client.logs.describe_resource_policies()
        policy_names = [p["policyName"] for p in response["resourcePolicies"]]
        assert policy_name not in policy_names

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_delete_resource_policy_not_found(self, aws_client, snapshot):
        """Test deleting a non-existent resource policy."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_resource_policy(policyName="non-existent")
        snapshot.match("error-policy-not-found", ctx.value.response)


class TestResourcePoliciesLimits:
    """Tests for resource policy limit enforcement."""

    @markers.aws.validated
    def test_put_resource_policy_limit_exceeded(self, aws_client, snapshot, cleanups):
        """Test that creating more than MAX_RESOURCE_POLICIES_PER_REGION fails."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        prefix = f"test-policy-limit-{short_uid()}"

        # Create the maximum number of resource policies
        for idx in range(MAX_RESOURCE_POLICIES_PER_REGION):
            policy_name = f"{prefix}-{idx}"
            aws_client.logs.put_resource_policy(
                policyName=policy_name, policyDocument=JSON_POLICY_DOC
            )
            cleanups.append(
                lambda pn=policy_name: aws_client.logs.delete_resource_policy(policyName=pn)
            )

        # Try to create one more - should fail
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_resource_policy(
                policyName=f"{prefix}-too-many", policyDocument=JSON_POLICY_DOC
            )
        snapshot.match("error-limit-exceeded", ctx.value.response)

    @markers.aws.validated
    def test_put_resource_policy_update_existing_when_at_limit(self, aws_client, cleanups):
        """Test that updating existing policy works even when at limit."""
        prefix = f"test-policy-limit-{short_uid()}"

        # Create the maximum number of resource policies
        for idx in range(MAX_RESOURCE_POLICIES_PER_REGION):
            policy_name = f"{prefix}-{idx}"
            aws_client.logs.put_resource_policy(
                policyName=policy_name, policyDocument=JSON_POLICY_DOC
            )
            cleanups.append(
                lambda pn=policy_name: aws_client.logs.delete_resource_policy(policyName=pn)
            )

        # Update an existing policy - should succeed
        new_document = '{"Statement":[{"Action":"logs:*","Effect":"Allow","Principal":{"Service":"logs.amazonaws.com"},"Resource":"*"}]}'
        response = aws_client.logs.put_resource_policy(
            policyName=f"{prefix}-1", policyDocument=new_document
        )

        assert response["resourcePolicy"]["policyDocument"] == new_document
