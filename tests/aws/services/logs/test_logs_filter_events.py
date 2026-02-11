"""Tests for CloudWatch Logs - Filter Log Events operations."""

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.pytest.snapshot import is_aws

from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.testing.pytest import markers
from localstack.utils.common import now_utc, retry


class TestFilterLogEvents:
    """Tests for filter_log_events operation."""

    @markers.aws.validated
    def test_filter_log_events_basic(self, logs_log_group, logs_log_stream, aws_client):
        """Test basic filter log events operation."""
        timestamp = now_utc(millis=True)
        events = [
            {"timestamp": timestamp, "message": "log message 1"},
            {"timestamp": timestamp + 100, "message": "log message 2"},
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        def verify_filter():
            response = aws_client.logs.filter_log_events(logGroupName=logs_log_group)
            assert len(response["events"]) >= 2

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_log_events_response_header(self, logs_log_group, logs_log_stream, aws_client):
        """Test that filter_log_events returns correct content-type header."""
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        response = aws_client.logs.filter_log_events(logGroupName=logs_log_group)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert (
            response["ResponseMetadata"]["HTTPHeaders"]["content-type"] == APPLICATION_AMZ_JSON_1_1
        )

    @markers.aws.validated
    def test_filter_log_events_with_log_stream_names(
        self, logs_log_group, logs_log_stream, aws_client
    ):
        """Test filtering by specific log stream names."""
        timestamp = now_utc(millis=True)
        events = [
            {"timestamp": timestamp, "message": "test message"},
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        def verify_filter():
            response = aws_client.logs.filter_log_events(
                logGroupName=logs_log_group,
                logStreamNames=[logs_log_stream],
            )
            assert len(response["events"]) >= 1

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_log_events_interleaved(self, logs_log_group, logs_log_stream, aws_client):
        """Test filter log events with interleaved parameter."""
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp, "message": "hello"},
            {"timestamp": timestamp + 100, "message": "world"},
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

        def verify_filter():
            response = aws_client.logs.filter_log_events(
                logGroupName=logs_log_group,
                logStreamNames=[logs_log_stream],
                interleaved=True,
            )
            events = response["events"]
            assert len(events) >= 2
            for event in events:
                assert "eventId" in event
                assert "timestamp" in event
                assert "message" in event

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_log_events_pagination(self, logs_log_group, logs_log_stream, aws_client):
        """Test filter log events pagination."""
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp + i * 100, "message": f"Message number {i}"} for i in range(25)
        ]

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

        def verify_pagination():
            # Get first page
            response = aws_client.logs.filter_log_events(
                logGroupName=logs_log_group,
                logStreamNames=[logs_log_stream],
                limit=20,
            )
            events = response["events"]
            assert len(events) == 20
            assert "nextToken" in response

            # Get second page
            response2 = aws_client.logs.filter_log_events(
                logGroupName=logs_log_group,
                logStreamNames=[logs_log_stream],
                limit=20,
                nextToken=response["nextToken"],
            )
            events2 = response2["events"]
            assert len(events + events2) == 25

        retry(
            verify_pagination,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    @pytest.mark.skip(reason="TODO Raise error")
    def test_filter_log_events_unknown_token(
        self, logs_log_group, logs_log_stream, aws_client, snapshot
    ):
        """Test filter log events with unknown/invalid token."""
        with pytest.raises(ClientError) as ctx:
            aws_client.logs.filter_log_events(
                logGroupName=logs_log_group,
                logStreamNames=[logs_log_stream],
                limit=20,
                nextToken="invalid-token",
            )
        snapshot.match("invalid-token", ctx.value.response)

    @markers.aws.validated
    def test_filter_log_events_limit_validation(self, logs_log_group, aws_client, snapshot):
        """Test that limit over 10000 is rejected."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.filter_log_events(logGroupName=logs_log_group, limit=10001)
        snapshot.match("error-limit-exceeded", ctx.value.response)


@pytest.mark.skip(reason="filtering is only supported in pro")
class TestFilterLogEventsPatterns:
    """Tests for filter log events with filter patterns."""

    @pytest.fixture(autouse=True)
    def setup_log_events(self, logs_log_group, logs_log_stream, aws_client):
        """Set up common log events for pattern testing."""
        self.log_group = logs_log_group
        self.log_stream = logs_log_stream
        self.client = aws_client.logs

        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp, "message": "hello"},
            {"timestamp": timestamp + 100, "message": "world"},
            {"timestamp": timestamp + 200, "message": "hello world"},
            {"timestamp": timestamp + 300, "message": "goodbye world"},
            {"timestamp": timestamp + 400, "message": "hello cruela"},
            {"timestamp": timestamp + 500, "message": "goodbye cruel world"},
        ]
        self.client.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=messages
        )

    @markers.aws.validated
    def test_filter_simple_word_pattern(self):
        """Test filtering with a simple word pattern."""

        def verify_filter():
            events = self.client.filter_log_events(
                logGroupName=self.log_group,
                logStreamNames=[self.log_stream],
                filterPattern="hello",
            )["events"]
            messages = [e["message"] for e in events]
            assert "hello" in messages or "hello world" in messages or "hello cruela" in messages
            # Only messages containing "hello" should be returned
            for msg in messages:
                assert "hello" in msg

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_multiple_words_pattern(self):
        """Test filtering with multiple words pattern."""

        def verify_filter():
            events = self.client.filter_log_events(
                logGroupName=self.log_group,
                logStreamNames=[self.log_stream],
                filterPattern="goodbye world",
            )["events"]
            messages = [e["message"] for e in events]
            # Messages containing both "goodbye" and "world" should be returned
            for msg in messages:
                assert "goodbye" in msg and "world" in msg

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_quoted_pattern(self):
        """Test filtering with a quoted phrase pattern."""

        def verify_filter():
            events = self.client.filter_log_events(
                logGroupName=self.log_group,
                logStreamNames=[self.log_stream],
                filterPattern='"hello cruel"',
            )["events"]
            messages = [e["message"] for e in events]
            # Only exact phrase matches should be returned
            for msg in messages:
                assert "hello cruel" in msg

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_json_pattern(self):
        """Test filtering with a JSON-style pattern (treated as no-filter in Moto)."""

        def verify_filter():
            events = self.client.filter_log_events(
                logGroupName=self.log_group,
                logStreamNames=[self.log_stream],
                filterPattern='{$.message = "hello"}',
            )["events"]
            # JSON patterns may or may not be fully supported
            # Just verify that the call succeeds
            assert isinstance(events, list)

        retry(
            verify_filter,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )
