"""Tests for CloudWatch Logs - Log Stream operations."""

import pytest

from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.common import short_uid


def _log_stream_exists(log_streams: list, name: str) -> bool:
    """Check if a log stream with the given name exists in the list."""
    return any(ls["logStreamName"] == name for ls in log_streams)


@pytest.fixture
def logs_log_group(aws_client):
    """Create a log group for testing and clean up afterwards."""
    name = f"test-log-group-{short_uid()}"
    aws_client.logs.create_log_group(logGroupName=name)
    yield name
    aws_client.logs.delete_log_group(logGroupName=name)


class TestLogsStreams:
    """Tests for log stream create, delete, describe operations."""

    @markers.aws.validated
    def test_create_and_delete_log_stream(self, logs_log_group, aws_client, snapshot):
        """Test basic log stream creation and deletion."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        stream_name = f"test-log-stream-{short_uid()}"

        # Create log stream
        aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=stream_name)
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group>"))

        # Verify stream exists
        response = aws_client.logs.describe_log_streams(logGroupName=logs_log_group)
        snapshot.match("describe-log-streams-after-create", response)
        assert _log_stream_exists(response["logStreams"], stream_name)

        # Delete log stream
        aws_client.logs.delete_log_stream(logGroupName=logs_log_group, logStreamName=stream_name)

        # Verify stream is deleted
        response = aws_client.logs.describe_log_streams(logGroupName=logs_log_group)
        assert not _log_stream_exists(response.get("logStreams", []), stream_name)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_create_log_stream_duplicate_error(
        self, logs_log_group, aws_client, snapshot, cleanups
    ):
        """Test that creating a duplicate log stream raises an error."""
        stream_name = f"test-log-stream-{short_uid()}"
        aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=stream_name)
        cleanups.append(
            lambda: aws_client.logs.delete_log_stream(
                logGroupName=logs_log_group, logStreamName=stream_name
            )
        )

        with pytest.raises(Exception) as ctx:
            aws_client.logs.create_log_stream(
                logGroupName=logs_log_group, logStreamName=stream_name
            )
        snapshot.match("error-duplicate-log-stream", ctx.value.response)

    @markers.aws.validated
    def test_describe_log_streams_with_log_group_identifier(
        self, logs_log_group, aws_client, region_name, snapshot
    ):
        """Test describing log streams using logGroupIdentifier parameter."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group>"))
        stream_name = f"test-log-stream-{short_uid()}"
        aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=stream_name)

        # Using logGroupIdentifier with name
        response = aws_client.logs.describe_log_streams(logGroupIdentifier=logs_log_group)
        snapshot.match("describe-streams-identifier-name", response)
        assert _log_stream_exists(response["logStreams"], stream_name)

        # Using logGroupIdentifier with ARN
        account_id = aws_client.sts.get_caller_identity()["Account"]
        log_group_arn = arns.log_group_arn(
            logs_log_group,
            account_id=account_id,
            region_name=region_name,
        )
        response = aws_client.logs.describe_log_streams(logGroupIdentifier=log_group_arn)
        snapshot.match("describe-streams-identifier-arn", response)
        assert _log_stream_exists(response["logStreams"], stream_name)

        # Using both logGroupName and logGroupIdentifier should raise error
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_log_streams(
                logGroupName=logs_log_group, logGroupIdentifier=logs_log_group
            )
        snapshot.match("error-both-name-and-identifier", ctx.value.response)

    @markers.aws.validated
    def test_describe_log_streams_with_prefix(self, logs_log_group, aws_client, snapshot, cleanups):
        """Test describing log streams with prefix filter."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group>"))
        prefix = f"test-prefix-{short_uid()}"
        stream_names = [f"{prefix}-stream-{i}" for i in range(3)]

        for name in stream_names:
            aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=name)
            cleanups.append(
                lambda n=name: aws_client.logs.delete_log_stream(
                    logGroupName=logs_log_group, logStreamName=n
                )
            )

        response = aws_client.logs.describe_log_streams(
            logGroupName=logs_log_group, logStreamNamePrefix=prefix
        )
        snapshot.match("describe-streams-with-prefix", response)
        for name in stream_names:
            assert _log_stream_exists(response["logStreams"], name)

    @markers.aws.validated
    def test_log_stream_arn_format(self, logs_log_group, aws_client, region_name, snapshot):
        """Test that log stream ARN is in the correct format."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group>"))
        stream_name = f"test-arn-{short_uid()}"
        aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=stream_name)

        response = aws_client.logs.describe_log_streams(logGroupName=logs_log_group)
        snapshot.match("describe-log-streams-with-arn", response)

        stream = response["logStreams"][0]
        account_id = aws_client.sts.get_caller_identity()["Account"]

        # Verify ARN format
        expected_arn = (
            f"arn:aws:logs:{region_name}:{account_id}:"
            f"log-group:{logs_log_group}:log-stream:{stream_name}"
        )
        assert stream["arn"] == expected_arn
