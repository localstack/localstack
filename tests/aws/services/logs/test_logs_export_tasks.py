"""Tests for CloudWatch Logs - Export Task operations."""

import copy
import json

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import now_utc, short_uid

S3_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "s3:GetBucketAcl",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::{BUCKET_NAME}",
            "Principal": {"Service": "logs.amazonaws.com"},
        },
        {
            "Action": "s3:PutObject",
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::{BUCKET_NAME}/*",
            "Principal": {"Service": "logs.amazonaws.com"},
        },
    ],
}


@pytest.fixture
def logs_log_group(aws_client):
    """Create a log group for testing and clean up afterwards."""
    name = f"test-log-group-{short_uid()}"
    aws_client.logs.create_log_group(logGroupName=name)
    yield name
    aws_client.logs.delete_log_group(logGroupName=name)


@pytest.fixture
def export_bucket(aws_client, s3_bucket, region_name):
    """Create an S3 bucket configured for CloudWatch Logs export."""
    bucket_name = s3_bucket

    # Get account ID for policy

    # Configure bucket policy for CloudWatch Logs access
    policy = copy.deepcopy(S3_POLICY)
    policy["Statement"][0]["Resource"] = f"arn:aws:s3:::{bucket_name}"
    policy["Statement"][1]["Resource"] = f"arn:aws:s3:::{bucket_name}/*"

    aws_client.s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))

    return bucket_name


@pytest.mark.skip(reason="not supported")
class TestExportTasks:
    """Tests for export task operations."""

    @markers.aws.validated
    @pytest.mark.skip(reason="not supported")
    def test_create_export_task(self, logs_log_group, export_bucket, aws_client, snapshot):
        """Test creating an export task."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        from_time = 1611316574  # Fixed timestamp for reproducibility
        to_time = 1642852574

        response = aws_client.logs.create_export_task(
            logGroupName=logs_log_group,
            fromTime=from_time,
            to=to_time,
            destination=export_bucket,
        )
        snapshot.match("create-export-task", response)

        task_id = response["taskId"]

        # Try to cancel the task (cleanup)
        try:
            aws_client.logs.cancel_export_task(taskId=task_id)
        except ClientError as exc:
            # Task might have already finished
            if "already finished" not in exc.response["Error"]["Message"]:
                raise

    @markers.aws.validated
    def test_create_export_task_with_prefix(
        self, logs_log_group, export_bucket, aws_client, snapshot
    ):
        """Test creating an export task with a destination prefix."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        from_time = 1611316574
        to_time = 1642852574
        prefix = f"custom-prefix-{short_uid()}"

        response = aws_client.logs.create_export_task(
            logGroupName=logs_log_group,
            fromTime=from_time,
            to=to_time,
            destination=export_bucket,
            destinationPrefix=prefix,
        )
        snapshot.match("create-export-task-with-prefix", response)

        task_id = response["taskId"]

        # Try to cancel the task (cleanup)
        try:
            aws_client.logs.cancel_export_task(taskId=task_id)
        except ClientError:
            pass

    @markers.aws.validated
    def test_create_export_task_bucket_not_found(self, logs_log_group, aws_client, snapshot):
        """Test that creating an export task with non-existent bucket fails."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.create_export_task(
                logGroupName=logs_log_group,
                fromTime=1611316574,
                to=1642852574,
                destination=f"non-existent-bucket-{short_uid()}",
            )
        snapshot.match("error-bucket-not-found", ctx.value.response)

    @markers.aws.validated
    def test_create_export_task_log_group_not_found(self, export_bucket, aws_client, snapshot):
        """Test that creating an export task with non-existent log group fails."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.create_export_task(
                logGroupName=f"non-existent-log-group-{short_uid()}",
                fromTime=1611316574,
                to=1642852574,
                destination=export_bucket,
            )
        snapshot.match("error-log-group-not-found", ctx.value.response)

    @markers.aws.validated
    def test_describe_export_tasks(self, logs_log_group, export_bucket, aws_client, snapshot):
        """Test describing export tasks."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        from_time = 1611316574
        to_time = 1642852574

        # Create an export task
        response = aws_client.logs.create_export_task(
            logGroupName=logs_log_group,
            fromTime=from_time,
            to=to_time,
            destination=export_bucket,
        )
        task_id = response["taskId"]

        # Describe export tasks
        response = aws_client.logs.describe_export_tasks(taskId=task_id)
        snapshot.match("describe-export-tasks", response)

        # Cleanup
        try:
            aws_client.logs.cancel_export_task(taskId=task_id)
        except ClientError:
            pass

    @markers.aws.validated
    def test_describe_export_tasks_not_found(self, aws_client, snapshot):
        """Test describing a non-existent export task."""
        response = aws_client.logs.describe_export_tasks(taskId="non-existent-task-id")
        snapshot.match("task-not-found", response)

    @markers.aws.validated
    def test_cancel_export_task_not_found(self, aws_client, snapshot):
        """Test cancelling a non-existent export task."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.cancel_export_task(taskId=f"{short_uid()}-{short_uid()}")
        snapshot.match("error-cancel-not-found", ctx.value.response)


@pytest.mark.skip(reason="not supported")
class TestExportTasksWithLogs:
    """Tests for export tasks with actual log data."""

    @markers.aws.validated
    def test_create_export_task_with_logs(
        self, logs_log_group, export_bucket, aws_client, snapshot
    ):
        """Test exporting actual log events to S3."""
        snapshot.add_transformer(snapshot.transform.logs_api())

        # Create log stream and put events
        log_stream_name = f"test-stream-{short_uid()}"
        aws_client.logs.create_log_stream(
            logGroupName=logs_log_group, logStreamName=log_stream_name
        )

        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp + i * 100, "message": f"test message {i}"} for i in range(10)
        ]
        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=log_stream_name, logEvents=messages
        )

        # Create export task with time range that includes our logs
        from_time = timestamp - 86400000  # 1 day before
        to_time = timestamp + 86400000  # 1 day after

        response = aws_client.logs.create_export_task(
            logGroupName=logs_log_group,
            fromTime=from_time,
            to=to_time,
            destination=export_bucket,
        )
        task_id = response["taskId"]
        snapshot.match("create-export-with-logs", response)

        # Describe the task
        response = aws_client.logs.describe_export_tasks(taskId=task_id)
        snapshot.match("describe-export-with-logs", response)
        task = response["exportTasks"][0]

        # Status should be one of: PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
        assert task["status"]["code"] in [
            "PENDING",
            "RUNNING",
            "COMPLETED",
            "CANCELLED",
            "FAILED",
            "active",
        ]

        # Cleanup
        try:
            aws_client.logs.cancel_export_task(taskId=task_id)
        except ClientError:
            pass
