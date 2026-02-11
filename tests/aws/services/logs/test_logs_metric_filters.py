"""Tests for CloudWatch Logs - Metric Filter operations."""

import pytest
from localstack_snapshot.pytest.snapshot import is_aws

from localstack.testing.pytest import markers
from localstack.utils.common import now_utc, retry, short_uid


class TestMetricFilters:
    """Tests for metric filter operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..metricFilters..applyOnTransformedLogs",
            "$..metricFilters..creationTime",
            "$..metricFilters..metricTransformations..defaultValue",
        ]
    )
    def test_put_metric_filter_basic(self, logs_log_group, aws_client, snapshot, cleanups):
        """Test basic metric filter creation."""
        filter_name = f"test-filter-{short_uid()}"
        namespace = f"test-namespace-{short_uid()}"
        metric_name = f"test-metric-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("filterName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricNamespace"))

        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=filter_name,
            filterPattern=" ",
            metricTransformations=[
                {
                    "metricNamespace": namespace,
                    "metricName": metric_name,
                    "metricValue": "1",
                    "defaultValue": 0,
                },
            ],
        )
        cleanups.append(
            lambda: aws_client.logs.delete_metric_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix=filter_name
        )
        snapshot.match("describe-metric-filters", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..metricFilters..applyOnTransformedLogs",
            "$..metricFilters..creationTime",
            "$..metricFilters..metricTransformations..defaultValue",
        ]
    )
    def test_put_metric_filter_json_pattern(self, logs_log_group, aws_client, snapshot, cleanups):
        """Test metric filter with JSON filter pattern."""
        filter_name = f"test-filter-json-{short_uid()}"
        namespace = f"test-namespace-{short_uid()}"
        metric_name = f"test-metric-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("filterName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricNamespace"))

        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=filter_name,
            filterPattern='{$.message = "test"}',
            metricTransformations=[
                {
                    "metricNamespace": namespace,
                    "metricName": metric_name,
                    "metricValue": "1",
                    "defaultValue": 0,
                },
            ],
        )
        cleanups.append(
            lambda: aws_client.logs.delete_metric_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix=filter_name
        )
        snapshot.match("describe-metric-filters-json", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..metricFilters..applyOnTransformedLogs", "$..metricFilters..creationTime"]
    )
    def test_describe_metric_filters_by_prefix(self, aws_client, snapshot, cleanups):
        """Test describing metric filters by name prefix."""

        prefix = f"test-filter-prefix-{short_uid()}"

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("filterName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricNamespace"))

        log_groups = []
        for i in range(2):
            log_group = f"test-log-group-{short_uid()}"
            aws_client.logs.create_log_group(logGroupName=log_group)
            log_groups.append(log_group)
            cleanups.append(lambda lg=log_group: aws_client.logs.delete_log_group(logGroupName=lg))

            aws_client.logs.put_metric_filter(
                logGroupName=log_group,
                filterName=f"{prefix}-{i}",
                filterPattern=f"filterPattern{i}",
                metricTransformations=[
                    {
                        "metricNamespace": f"namespace{i}",
                        "metricName": f"metric{i}",
                        "metricValue": str(i),
                    },
                ],
            )
            cleanups.append(
                lambda lg=log_group, fn=f"{prefix}-{i}": aws_client.logs.delete_metric_filter(
                    logGroupName=lg, filterName=fn
                )
            )

        response = aws_client.logs.describe_metric_filters(filterNamePrefix=prefix)
        snapshot.match("describe-by-prefix", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..applyOnTransformedLogs", "$..creationTime"])
    def test_describe_metric_filters_by_log_group(self, aws_client, snapshot, cleanups):
        """Test describing metric filters by log group name."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("filterName"))

        log_group1 = f"test-log-group-{short_uid()}"
        log_group2 = f"test-log-group-{short_uid()}"

        for log_group in [log_group1, log_group2]:
            aws_client.logs.create_log_group(logGroupName=log_group)
            cleanups.append(lambda lg=log_group: aws_client.logs.delete_log_group(logGroupName=lg))

            aws_client.logs.put_metric_filter(
                logGroupName=log_group,
                filterName=f"filter-{short_uid()}",
                filterPattern="pattern",
                metricTransformations=[
                    {
                        "metricNamespace": "namespace",
                        "metricName": "metric",
                        "metricValue": "1",
                    },
                ],
            )

        response = aws_client.logs.describe_metric_filters(logGroupName=log_group1)
        snapshot.match("describe-by-log-group", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..applyOnTransformedLogs", "$..creationTime"])
    def test_describe_metric_filters_by_metric_name(
        self, aws_client, snapshot, cleanups, logs_log_group
    ):
        """Test describing metric filters by metric name and namespace."""

        snapshot.add_transformer(snapshot.transform.logs_api())
        snapshot.add_transformer(snapshot.transform.key_value("filterName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricName"))
        snapshot.add_transformer(snapshot.transform.key_value("metricNamespace"))

        log_group = logs_log_group

        metric_name = f"test-metric-{short_uid()}"
        namespace = f"test-namespace-{short_uid()}"

        aws_client.logs.put_metric_filter(
            logGroupName=log_group,
            filterName=f"filter-{short_uid()}",
            filterPattern="pattern",
            metricTransformations=[
                {
                    "metricNamespace": namespace,
                    "metricName": metric_name,
                    "metricValue": "1",
                },
            ],
        )

        response = aws_client.logs.describe_metric_filters(
            metricName=metric_name, metricNamespace=namespace
        )
        snapshot.match("describe-by-metric-name", response)

    @markers.aws.validated
    def test_delete_metric_filter(self, logs_log_group, aws_client):
        """Test deleting a metric filter."""
        filter_name = f"test-filter-{short_uid()}"

        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=filter_name,
            filterPattern="{ $.val = * }",
            metricTransformations=[
                {
                    "metricNamespace": "namespace",
                    "metricName": "metric",
                    "metricValue": "$.value",
                },
            ],
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix=filter_name
        )
        assert len(response["metricFilters"]) == 1

        # Delete the filter
        aws_client.logs.delete_metric_filter(logGroupName=logs_log_group, filterName=filter_name)

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix=filter_name
        )
        assert len(response["metricFilters"]) == 0

    @markers.aws.validated
    def test_put_metric_filter_with_special_namespace(self, logs_log_group, aws_client, cleanups):
        """Test metric filter with special characters in namespace."""
        filter_name = f"test-filter-{short_uid()}"
        namespace = "A.B-c_d/1#2:metricNamespace"  # Valid namespace with special chars

        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=filter_name,
            filterPattern="filterPattern",
            metricTransformations=[
                {
                    "metricNamespace": namespace,
                    "metricName": "metricName",
                    "metricValue": "1",
                },
            ],
        )
        cleanups.append(
            lambda: aws_client.logs.delete_metric_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )
        )

        response = aws_client.logs.describe_metric_filters(
            metricName="metricName", metricNamespace=namespace
        )
        assert len(response["metricFilters"]) == 1
        assert response["metricFilters"][0]["filterName"] == filter_name


class TestMetricFiltersValidation:
    """Tests for metric filter validation."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_put_metric_filter_invalid_filter_name(self, logs_log_group, aws_client, snapshot):
        """Test that filter names over 512 characters are rejected."""
        invalid_filter_name = "X" * 513

        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_metric_filter(
                logGroupName=logs_log_group,
                filterName=invalid_filter_name,
                filterPattern="pattern",
                metricTransformations=[
                    {
                        "metricNamespace": "namespace",
                        "metricName": "metric",
                        "metricValue": "1",
                    },
                ],
            )
        snapshot.match("error-invalid-filter-name", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_put_metric_filter_invalid_filter_pattern(self, logs_log_group, aws_client, snapshot):
        """Test that filter patterns over 1024 characters are rejected."""
        invalid_filter_pattern = "X" * 1025

        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_metric_filter(
                logGroupName=logs_log_group,
                filterName="valid-filter",
                filterPattern=invalid_filter_pattern,
                metricTransformations=[
                    {
                        "metricNamespace": "namespace",
                        "metricName": "metric",
                        "metricValue": "1",
                    },
                ],
            )
        snapshot.match("error-invalid-filter-pattern", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_put_metric_filter_too_many_transformations(self, logs_log_group, aws_client, snapshot):
        """Test that more than 1 metric transformation is rejected."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_metric_filter(
                logGroupName=logs_log_group,
                filterName="valid-filter",
                filterPattern="pattern",
                metricTransformations=[
                    {
                        "metricNamespace": "namespace1",
                        "metricName": "metric1",
                        "metricValue": "1",
                    },
                    {
                        "metricNamespace": "namespace2",
                        "metricName": "metric2",
                        "metricValue": "1",
                    },
                ],
            )
        snapshot.match("error-too-many-transformations", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_delete_metric_filter_invalid_filter_name(self, logs_log_group, aws_client, snapshot):
        """Test delete metric filter with invalid filter name."""
        invalid_filter_name = "X" * 513

        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_metric_filter(
                logGroupName=logs_log_group, filterName=invalid_filter_name
            )
        snapshot.match("error-invalid-filter-name", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_delete_metric_filter_invalid_log_group_name(self, aws_client, snapshot):
        """Test delete metric filter with invalid log group name."""
        invalid_log_group_name = "X" * 513

        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_metric_filter(
                logGroupName=invalid_log_group_name, filterName="valid-filter"
            )
        snapshot.match("error-invalid-log-group-name", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Message"])
    def test_describe_metric_filters_invalid_parameters(self, aws_client, snapshot):
        """Test describe metric filters with invalid parameter lengths."""
        # Invalid filter name prefix (over 512 chars)
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_metric_filters(filterNamePrefix="X" * 513)
        snapshot.match("error-invalid-filter-prefix", ctx.value.response)

        # Invalid metric name (over 255 chars)
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_metric_filters(metricName="X" * 256, metricNamespace="valid")
        snapshot.match("error-invalid-metric-name", ctx.value.response)


class TestMetricFiltersCloudWatchIntegration:
    """Tests for metric filter integration with CloudWatch metrics."""

    @markers.aws.validated
    @pytest.mark.skip(reason="TODO - Fails against pro")
    def test_metric_filters_publish_to_cloudwatch(
        self, logs_log_group, logs_log_stream, aws_client
    ):
        """Test that metric filters publish metrics to CloudWatch."""
        basic_filter_name = f"test-filter-basic-{short_uid()}"
        json_filter_name = f"test-filter-json-{short_uid()}"
        namespace_name = f"test-metric-namespace-{short_uid()}"
        basic_metric_name = f"test-basic-metric-{short_uid()}"
        json_metric_name = f"test-json-metric-{short_uid()}"

        basic_transforms = {
            "metricNamespace": namespace_name,
            "metricName": basic_metric_name,
            "metricValue": "1",
            "defaultValue": 0,
        }
        json_transforms = {
            "metricNamespace": namespace_name,
            "metricName": json_metric_name,
            "metricValue": "1",
            "defaultValue": 0,
        }

        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=basic_filter_name,
            filterPattern=" ",
            metricTransformations=[basic_transforms],
        )
        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=json_filter_name,
            filterPattern='{$.message = "test"}',
            metricTransformations=[json_transforms],
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix="test-filter-"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        filter_names = [_filter["filterName"] for _filter in response["metricFilters"]]
        assert basic_filter_name in filter_names
        assert json_filter_name in filter_names

        # Put log events and assert metrics being published
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        # List metrics
        def list_metrics():
            res = aws_client.cloudwatch.list_metrics(Namespace=namespace_name)
            assert len(res["Metrics"]) == 2

        retry(
            list_metrics,
            retries=20 if is_aws() else 5,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

        # Delete filters
        aws_client.logs.delete_metric_filter(
            logGroupName=logs_log_group, filterName=basic_filter_name
        )
        aws_client.logs.delete_metric_filter(
            logGroupName=logs_log_group, filterName=json_filter_name
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix="test-filter-"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        filter_names = [_filter["filterName"] for _filter in response["metricFilters"]]
        assert basic_filter_name not in filter_names
        assert json_filter_name not in filter_names
