"""Tests for CloudWatch Logs - Insights Query operations."""

import time

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


def _get_query_results(aws_client, query_id):
    def _assert_query_status():
        query_results = aws_client.logs.get_query_results(queryId=query_id)
        assert query_results["status"] in ["Complete"]
        return query_results

    return retry(
        _assert_query_status,
        retries=20 if is_aws() else 3,
        sleep=5 if is_aws() else 1,
        sleep_before=3 if is_aws() else 0,
    )


class TestCloudWatchLogsInsightsQueries:
    """Tests for CloudWatch Logs Insights query operations."""

    @markers.aws.validated
    def test_start_query_basic(self, logs_log_group, aws_client, snapshot):
        """Test starting a basic query."""
        snapshot.add_transformer(snapshot.transform.logs_api())

        response = aws_client.logs.start_query(
            logGroupName=logs_log_group,
            startTime=int(time.time()) - 3600,  # 1 hour ago
            endTime=int(time.time()) + 300,  # 5 minutes from now
            queryString="fields @message",
        )
        snapshot.match("start-query", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_start_query_log_group_not_found(self, aws_client, snapshot):
        """Test starting a query on a non-existent log group."""
        log_group = f"non-existent-{short_uid()}"
        with pytest.raises(Exception) as ctx:
            aws_client.logs.start_query(
                logGroupName=log_group,
                startTime=int(time.time()) - 3600,
                endTime=int(time.time()) + 300,
                queryString="fields @message",
            )
        snapshot.add_transformer(snapshot.transform.regex(log_group, "<log-group>"))
        snapshot.match("error-log-group-not-found", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..queries..createTime",
            "$..queries..queryLanguage",
            "$..queries..queryString",
            "$..queries..status",
        ]
    )
    def test_describe_queries(self, logs_log_group, aws_client, snapshot):
        """Test describing queries for a log group."""

        start_time = int(time.time()) - 3600
        end_time = int(time.time()) + 300

        # Start a query
        aws_client.logs.start_query(
            logGroupName=logs_log_group,
            startTime=start_time,
            endTime=end_time,
            queryString="fields @message",
        )

        # Describe queries
        response = aws_client.logs.describe_queries(logGroupName=logs_log_group)

        snapshot.add_transformer(snapshot.transform.key_value("logGroupName"))
        snapshot.match("describe-queries", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..queries..queryLanguage", "$..queries..queryString"]
    )
    def test_describe_queries_with_status_filter(self, logs_log_group, aws_client, snapshot):
        """Test decscribing queries with status filter."""

        start_time = int(time.time()) - 3600
        end_time = int(time.time()) + 300

        # Start a query
        aws_client.logs.start_query(
            logGroupName=logs_log_group,
            startTime=start_time,
            endTime=end_time,
            queryString="fields @message",
        )

        # Describe queries with Complete status
        def describe_complete_queries():
            response = aws_client.logs.describe_queries(
                logGroupName=logs_log_group, status="Complete"
            )
            return response

        response = retry(
            describe_complete_queries,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(
            snapshot.transform.key_value("createTime", reference_replacement=False)
        )
        snapshot.add_transformer(snapshot.transform.key_value("status"))
        snapshot.add_transformer(snapshot.transform.regex(str(start_time), "<start-time>"))
        snapshot.add_transformer(snapshot.transform.regex(str(end_time), "<end-time>"))
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group>"))

        snapshot.match("describe-queries-complete", response)

        # Query with Scheduled status should return different results
        response = aws_client.logs.describe_queries(logGroupName=logs_log_group, status="Scheduled")
        snapshot.match("describe-queries-scheduled", response)

    @markers.aws.validated
    def test_describe_queries_empty(self, aws_client, cleanups):
        """Test describing queries for a log group with no queries."""
        log_group_name = f"test-log-group-{short_uid()}"
        aws_client.logs.create_log_group(logGroupName=log_group_name)
        cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

        response = aws_client.logs.describe_queries(logGroupName=log_group_name)
        assert response["queries"] == []


class TestCloudWatchLogsInsightsQueryStrings:
    """Tests for various CloudWatch Logs Insights query string patterns."""

    def _populate_log_group(self, aws_client, log_group_name, log_stream_name):
        # Put some log events
        timestamp = now_utc(millis=True)
        messages = [
            {"timestamp": timestamp - (i * 1000), "message": f"event nr {i}"} for i in range(5)
        ]
        messages.reverse()
        aws_client.logs.put_log_events(
            logGroupName=log_group_name, logStreamName=log_stream_name, logEvents=messages
        )

    def _query_results(self, aws_client, log_group_name, query):
        # Start a query
        start_time = now_utc() - 600  # 10 minutes ago
        end_time = start_time + 1200  # 10 minutes from now

        def run_query_and_get_results():
            # Get query results (may need to wait for completion)
            query_id = aws_client.logs.start_query(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                queryString=query,
            )["queryId"]
            results = _get_query_results(aws_client, query_id)
            assert len(results["results"])
            return results

        return retry(
            run_query_and_get_results,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.needs_fixing  # The query results are not matching
    def test_get_query_results(self, logs_log_group, logs_log_stream, aws_client):
        """Test getting query results."""

        self._populate_log_group(aws_client, logs_log_group, logs_log_stream)
        response = self._query_results(aws_client, logs_log_group, "fields @message")

        # TODO FIX issue with Logs returning only one message
        assert len(response["results"]) >= 1

        fields = {row["field"] for result in response["results"] for row in result}
        assert "@message" in fields or "@ptr" in fields

    @markers.aws.needs_fixing
    def test_query_with_limit(self, logs_log_group, logs_log_stream, aws_client):
        """Test query with limit clause."""

        self._populate_log_group(aws_client, logs_log_group, logs_log_stream)
        response = self._query_results(aws_client, logs_log_group, "fields @message | limit 5")

        # TODO FIX issue with Logs returning only one message
        assert len(response["results"]) <= 5

    @markers.aws.needs_fixing
    def test_query_with_sort(self, logs_log_group, logs_log_stream, aws_client):
        """Test query with sort clause."""

        self._populate_log_group(aws_client, logs_log_group, logs_log_stream)
        response = self._query_results(
            aws_client, logs_log_group, "fields @timestamp, @message | sort @timestamp desc"
        )

        # TODO FIX issue with Logs returning only one message
        assert len(response["results"])
