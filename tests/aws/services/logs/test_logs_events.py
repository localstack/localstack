"""Tests for CloudWatch Logs - Log Event operations."""

import pytest
from localstack_snapshot.pytest.snapshot import is_aws

from localstack.testing.pytest import markers
from localstack.utils.common import now_utc, retry, short_uid


@pytest.fixture
def logs_log_group(aws_client):
    """Create a log group for testing and clean up afterwards."""
    name = f"test-log-group-{short_uid()}"
    aws_client.logs.create_log_group(logGroupName=name)
    yield name
    aws_client.logs.delete_log_group(logGroupName=name)


@pytest.fixture
def logs_log_stream(logs_log_group, aws_client):
    """Create a log stream for testing and clean up afterwards."""
    name = f"test-log-stream-{short_uid()}"
    aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=name)
    yield name
    aws_client.logs.delete_log_stream(logStreamName=name, logGroupName=logs_log_group)


class TestLogsEvents:
    """Tests for put and get log event operations."""

    @markers.aws.validated
    def test_put_log_events_basic(self, logs_log_group, logs_log_stream, aws_client):
        """Test basic log event insertion."""
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp, "message": "hello"},
            {"timestamp": timestamp, "message": "world"},
        ]

        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # Verify nextSequenceToken is returned
        next_sequence_token = response.get("nextSequenceToken")
        if next_sequence_token:
            assert isinstance(next_sequence_token, str)

    @markers.aws.validated
    def test_put_events_multi_bytes_msg(self, logs_log_group, logs_log_stream, aws_client):
        """Test log events with multi-byte characters (Unicode)."""
        body_msg = "🙀 - 参よ - 日本語"
        events = [{"timestamp": now_utc(millis=True), "message": body_msg}]

        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        def get_log_events():
            events = aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream
            )["events"]
            assert events[0]["message"] == body_msg

        retry(
            get_log_events,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_put_log_events_to_invalid_stream(self, logs_log_group, aws_client, snapshot):
        """Test that putting events to non-existent stream raises error."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_log_events(
                logGroupName=logs_log_group,
                logStreamName="invalid-stream",
                logEvents=[{"timestamp": now_utc(millis=True), "message": "test"}],
            )
        snapshot.match("error-invalid-stream", ctx.value.response)

    @markers.aws.validated
    def test_put_log_events_wrong_order(
        self, logs_log_group, logs_log_stream, aws_client, snapshot
    ):
        """Test that events in wrong chronological order are rejected."""
        ts_1 = now_utc(millis=True)
        ts_2 = now_utc(millis=True) - 86400000 * 2  # 2 days ago

        messages = [
            {"message": "Message 0", "timestamp": ts_1},
            {"message": "Message 1", "timestamp": ts_2},  # Older timestamp after newer one
        ]

        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
            )
        snapshot.match("error-wrong-order", ctx.value.response)

    @markers.aws.validated
    @pytest.mark.skip(reason="not supported")
    def test_put_log_events_too_old(self, logs_log_group, logs_log_stream, aws_client, snapshot):
        """Test that events with timestamps too far in the past are rejected."""
        # Event from 15 days ago
        timestamp = now_utc(millis=True) - 86400000 * 30

        messages = [{"message": "Old message", "timestamp": timestamp}]

        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )
        snapshot.match("response-too-old", response)
        assert "rejectedLogEventsInfo" in response
        assert "tooOldLogEventEndIndex" in response["rejectedLogEventsInfo"]

    @markers.aws.validated
    @pytest.mark.skip(reason="not supported")
    def test_put_log_events_too_new(self, logs_log_group, logs_log_stream, aws_client, snapshot):
        """Test that events with timestamps too far in the future are rejected."""
        # Event 3 hours in the future (>180 minutes)
        timestamp = now_utc(millis=True) + 86400000 * 1

        messages = [{"message": "Future message", "timestamp": timestamp}]

        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )
        snapshot.match("response-too-new", response)
        assert "rejectedLogEventsInfo" in response
        assert "tooNewLogEventStartIndex" in response["rejectedLogEventsInfo"]

    @markers.aws.validated
    def test_get_log_events_basic(self, logs_log_group, logs_log_stream, aws_client):
        """Test basic log event retrieval."""
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp, "message": "message 1"},
            {"timestamp": timestamp + 100, "message": "message 2"},
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

        def verify_events():
            response = aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream
            )
            events = response["events"]
            assert len(events) == 2
            assert events[0]["message"] == "message 1"
            assert events[1]["message"] == "message 2"

        retry(
            verify_events,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_get_log_events_start_from_head(self, logs_log_group, logs_log_stream, aws_client):
        """Test log event retrieval with startFromHead=True."""
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp + i * 100, "message": f"message {i}"} for i in range(20)
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

        def verify_events():
            response = aws_client.logs.get_log_events(
                logGroupName=logs_log_group,
                logStreamName=logs_log_stream,
                limit=10,
                startFromHead=True,
            )
            events = response["events"]
            assert len(events) == 10
            # First event should be message 0 when starting from head
            assert events[0]["message"] == "message 0"
            return response

        retry(
            verify_events,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_get_log_events_invalid_token(
        self, logs_log_group, logs_log_stream, aws_client, snapshot
    ):
        """Test that invalid nextToken is rejected."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_log_events(
                logGroupName=logs_log_group,
                logStreamName=logs_log_stream,
                nextToken="invalid-token",
            )
        snapshot.match("error-invalid-token", ctx.value.response)

    @markers.aws.validated
    def test_get_log_events_limit_validation(
        self, logs_log_group, logs_log_stream, aws_client, snapshot
    ):
        """Test that limit over 10000 is rejected."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream, limit=10001
            )
        snapshot.match("error-limit-exceeded", ctx.value.response)

    @markers.aws.validated
    def test_get_log_events_using_log_group_identifier(
        self, logs_log_group, logs_log_stream, aws_client, region_name, account_id
    ):
        """Test getting log events using logGroupIdentifier parameter."""
        timestamp = now_utc(millis=True)
        messages = [{"timestamp": timestamp, "message": "test message"}]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

        def verify_events():
            # Using logGroupName
            response1 = aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream
            )
            assert len(response1["events"]) >= 1

            # Using logGroupIdentifier with name
            response2 = aws_client.logs.get_log_events(
                logGroupIdentifier=logs_log_group, logStreamName=logs_log_stream
            )
            assert len(response2["events"]) >= 1

            # Using logGroupIdentifier with ARN
            log_group_arn = f"arn:aws:logs:{region_name}:{account_id}:log-group:{logs_log_group}"
            response3 = aws_client.logs.get_log_events(
                logGroupIdentifier=log_group_arn, logStreamName=logs_log_stream
            )
            assert len(response3["events"]) >= 1

        retry(
            verify_events,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )


class TestLogsEventsErrors:
    """Tests for log event error handling."""

    @markers.aws.validated
    def test_resource_does_not_exist(self, aws_client, snapshot, cleanups):
        """Test error handling when log group or stream doesn't exist."""
        log_group_name = f"log-group-{short_uid()}"
        log_stream_name = f"log-stream-{short_uid()}"

        # Log group doesn't exist
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )
        snapshot.match("error-log-group-does-not-exist", ctx.value.response)

        # Create log group
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        # Log stream doesn't exist
        with pytest.raises(Exception) as ctx:
            aws_client.logs.get_log_events(
                logGroupName=log_group_name, logStreamName=log_stream_name
            )
        snapshot.match("error-log-stream-does-not-exist", ctx.value.response)
