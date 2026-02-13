"""Tests for CloudWatch Logs - Log Group operations."""

import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import poll_condition, short_uid


def _log_group_exists(log_groups: list, name: str) -> bool:
    """Check if a log group with the given name exists in the list."""
    return any(lg["logGroupName"] == name for lg in log_groups)


class TestLogsGroups:
    """Tests for log group create, delete, describe operations."""

    @markers.aws.validated
    def test_create_and_delete_log_group(self, aws_client):
        """Test basic log group creation and deletion."""
        test_name = f"test-log-group-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=test_name)

        def log_group_created():
            log_groups = aws_client.logs.describe_log_groups(logGroupNamePrefix=test_name).get(
                "logGroups", []
            )
            return _log_group_exists(log_groups, test_name)

        assert poll_condition(log_group_created, timeout=5.0, interval=0.5)

        aws_client.logs.delete_log_group(logGroupName=test_name)

        def log_group_deleted():
            log_groups = aws_client.logs.describe_log_groups(logGroupNamePrefix=test_name).get(
                "logGroups", []
            )
            return not _log_group_exists(log_groups, test_name)

        assert poll_condition(log_group_deleted, timeout=5.0, interval=0.5)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..logGroups..deletionProtectionEnabled"])
    def test_create_log_group_with_kms_key(
        self, aws_client, snapshot, cleanups, kms_create_key, region_name, account_id
    ):
        """Test log group creation with KMS encryption."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-log-group-kms-{short_uid()}"

        kms_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "kms:*",
                    "Resource": "*",
                },
            ],
        }

        kms_key = kms_create_key(Policy=json.dumps(kms_policy))
        snapshot.add_transformer(snapshot.transform.regex(kms_key["KeyId"], "<key-id>"))

        aws_client.logs.create_log_group(logGroupName=log_group_name, kmsKeyId=kms_key["Arn"])
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        snapshot.match("describe-log-groups-with-kms", response)

        assert _log_group_exists(response["logGroups"], log_group_name)
        log_group = next(lg for lg in response["logGroups"] if lg["logGroupName"] == log_group_name)
        assert "kmsKeyId" in log_group

    @markers.aws.validated
    def test_create_log_group_duplicate_error(self, aws_client, snapshot, cleanups):
        """Test that creating a duplicate log group raises an error."""
        log_group_name = f"test-log-group-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        with pytest.raises(Exception) as ctx:
            aws_client.logs.create_log_group(logGroupName=log_group_name)
        snapshot.match("error-duplicate-log-group", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_create_log_group_invalid_name_length(self, aws_client, snapshot):
        """Test that log group names over 512 characters are rejected."""
        log_group_name = "a" * 513

        with pytest.raises(Exception) as ctx:
            aws_client.logs.create_log_group(logGroupName=log_group_name)
        snapshot.match("error-invalid-name-length", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..logGroups..deletionProtectionEnabled"])
    def test_describe_log_groups_with_prefix(self, aws_client, snapshot, cleanups):
        """Test describing log groups with prefix filter."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        prefix = f"test-prefix-{short_uid()}"
        log_group_names = [f"{prefix}-group-{i}" for i in range(3)]

        for name in log_group_names:
            aws_client.logs.create_log_group(logGroupName=name)
            cleanups.append(lambda n=name: aws_client.logs.delete_log_group(logGroupName=n))

        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=prefix)
        snapshot.match("describe-log-groups-prefix", response)
        for name in log_group_names:
            assert _log_group_exists(response["logGroups"], name)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..describe-log-groups-pattern.logGroups..storedBytes",
            "$..describe-log-groups-pattern.nextToken",
        ]
    )
    def test_describe_log_groups_with_pattern(self, aws_client, snapshot, cleanups):
        """Test describing log groups with pattern filter."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        unique_id = short_uid()
        log_group_name = f"test-pattern-{unique_id}"

        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        # Pattern matching may take time on AWS
        def log_group_found_by_pattern():
            log_groups = aws_client.logs.describe_log_groups(logGroupNamePattern=unique_id).get(
                "logGroups", []
            )
            return _log_group_exists(log_groups, log_group_name)

        assert poll_condition(log_group_found_by_pattern, timeout=5.0, interval=0.5)

        response = aws_client.logs.describe_log_groups(logGroupNamePattern=unique_id)
        snapshot.match("describe-log-groups-pattern", response)

    @markers.aws.validated
    def test_describe_log_groups_prefix_and_pattern_error(self, aws_client, snapshot, cleanups):
        """Test that using both prefix and pattern raises an error."""
        log_group_name = f"test-log-group-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_log_groups(
                logGroupNamePattern=log_group_name, logGroupNamePrefix=log_group_name
            )
        snapshot.match("error-prefix-and-pattern", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..nextToken", "$..storedBytes"])
    def test_list_log_groups_with_pattern(self, aws_client, snapshot, cleanups):
        """Test listing log groups with pattern filter."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        unique_id = short_uid()
        log_group_name = f"test-list-{unique_id}"

        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        response = aws_client.logs.list_log_groups(logGroupNamePattern="no-such-group")
        assert not _log_group_exists(response.get("logGroups", []), log_group_name)
        snapshot.match("list-log-groups-no-match", response)

        def log_group_found_by_pattern():
            log_groups = aws_client.logs.describe_log_groups(logGroupNamePattern=unique_id).get(
                "logGroups", []
            )
            return _log_group_exists(log_groups, log_group_name)

        assert poll_condition(log_group_found_by_pattern, interval=0.5, timeout=5)
        response = aws_client.logs.describe_log_groups(logGroupNamePattern=unique_id).get(
            "logGroups", []
        )
        snapshot.match("list-log-groups-match", response)


class TestLogsGroupsRetention:
    """Tests for log group retention policy operations."""

    @markers.aws.validated
    def test_put_retention_policy(self, aws_client, cleanups):
        """Test setting retention policy on a log group."""
        log_group_name = f"test-retention-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        aws_client.logs.put_retention_policy(logGroupName=log_group_name, retentionInDays=7)

        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        assert response["logGroups"][0].get("retentionInDays") == 7

    @markers.aws.validated
    def test_delete_retention_policy(self, aws_client, cleanups):
        """Test deleting retention policy from a log group."""
        log_group_name = f"test-retention-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        # Set retention policy
        aws_client.logs.put_retention_policy(logGroupName=log_group_name, retentionInDays=7)

        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        assert response["logGroups"][0].get("retentionInDays") == 7

        # Delete retention policy
        aws_client.logs.delete_retention_policy(logGroupName=log_group_name)

        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
        assert response["logGroups"][0].get("retentionInDays") is None


class TestLogsGroupsTags:
    """Tests for log group tagging operations."""

    @markers.aws.validated
    def test_create_log_group_with_tags(self, aws_client, snapshot, cleanups):
        """Test creating a log group with initial tags."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-tags-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=log_group_name, tags={"env": "testing"})
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        snapshot.match("list-tags-after-create", response)
        assert response["tags"] == {"env": "testing"}

    @markers.aws.validated
    @pytest.mark.skip(reason="TODO list tags returns empty")
    def test_tag_log_group(self, aws_client, snapshot, cleanups):
        """Test adding tags to an existing log group using tag_log_group API."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-tags-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        # Add tags
        aws_client.logs.tag_log_group(
            logGroupName=log_group_name, tags={"tag_key_1": "tag_value_1"}
        )

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        snapshot.match("list-tags-after-tag", response)
        assert response["tags"] == {"tag_key_1": "tag_value_1"}

        # Add more tags
        aws_client.logs.tag_log_group(
            logGroupName=log_group_name, tags={"tag_key_2": "tag_value_2"}
        )

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        assert response["tags"] == {"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"}

        # Update existing tag
        aws_client.logs.tag_log_group(
            logGroupName=log_group_name, tags={"tag_key_1": "tag_value_XX"}
        )

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        assert response["tags"] == {"tag_key_1": "tag_value_XX", "tag_key_2": "tag_value_2"}

    @markers.aws.validated
    @pytest.mark.skip(reason="TODO list tags returns empty")
    def test_untag_log_group(self, aws_client, snapshot, cleanups):
        """Test removing tags from a log group using untag_log_group API."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-tags-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        # Add tags
        tags = {"tag_key_1": "tag_value_1", "tag_key_2": "tag_value_2"}
        aws_client.logs.tag_log_group(logGroupName=log_group_name, tags=tags)

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        assert response["tags"] == tags

        # Remove one tag
        aws_client.logs.untag_log_group(logGroupName=log_group_name, tags=["tag_key_1"])

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        snapshot.match("list-tags-after-untag", response)
        assert response["tags"] == {"tag_key_2": "tag_value_2"}

    @markers.aws.validated
    def test_tag_resource_api(self, aws_client, snapshot, cleanups):
        """Test tagging log group using the new tag_resource/untag_resource APIs."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        log_group_name = f"test-tags-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=log_group_name, tags={"env": "testing1"})
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        snapshot.match("list-tags-after-create", response)

        # Get the log group ARN (without trailing :*)
        log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
            "logGroups"
        ][0]["arn"].rstrip(":*")

        # Add tags using new API
        aws_client.logs.tag_resource(
            resourceArn=log_group_arn, tags={"test1": "val1", "test2": "val2"}
        )

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)

        snapshot.match("list-tags-log-group-after-tag-resource", response)
        snapshot.match("list-tags-for-resource-after-tag-resource", response_2)
        # Values should be the same
        assert response["tags"] == response_2["tags"]

        # Add a tag using old API
        aws_client.logs.tag_log_group(logGroupName=log_group_name, tags={"test3": "val3"})

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)

        snapshot.match("list-tags-log-group-after-tag-log-group", response)
        snapshot.match("list-tags-for-resource-after-tag-log-group", response_2)
        assert response["tags"] == response_2["tags"]

        # Untag using both APIs
        aws_client.logs.untag_log_group(logGroupName=log_group_name, tags=["test3"])
        aws_client.logs.untag_resource(resourceArn=log_group_arn, tagKeys=["env", "test1"])

        response = aws_client.logs.list_tags_log_group(logGroupName=log_group_name)
        response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)
        snapshot.match("list-tags-log-group-after-untag", response)
        snapshot.match("list-tags-for-resource-after-untag", response_2)

        assert response["tags"] == response_2["tags"]
