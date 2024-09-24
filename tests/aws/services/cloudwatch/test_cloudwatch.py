import copy
import gzip
import json
import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from urllib.request import Request, urlopen

import pytest
import requests
from botocore.exceptions import ClientError

from localstack import config
from localstack.services.cloudwatch.provider import PATH_GET_RAW_METRICS
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.config import TEST_AWS_ACCESS_KEY_ID
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import TransformerUtility
from localstack.utils.aws import arns
from localstack.utils.aws.request_context import mock_aws_request_headers
from localstack.utils.common import retry, short_uid, to_str
from localstack.utils.sync import poll_condition, wait_until

if TYPE_CHECKING:
    from mypy_boto3_logs import CloudWatchLogsClient
PUBLICATION_RETRIES = 5

LOG = logging.getLogger(__name__)


def is_old_provider():
    return os.environ.get("PROVIDER_OVERRIDE_CLOUDWATCH") == "v1" and not is_aws_cloud()


class TestCloudwatch:
    @markers.aws.validated
    def test_put_metric_data_values_list(self, snapshot, aws_client):
        metric_name = "test-metric"
        namespace = f"ns-{short_uid()}"
        utc_now = datetime.utcnow().replace(tzinfo=timezone.utc)
        snapshot.add_transformer(
            snapshot.transform.key_value("Timestamp", reference_replacement=False)
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": utc_now,
                    "Values": [1.0, 10.0],
                    "Counts": [2, 4],
                    "Unit": "Count",
                }
            ],
        )

        def get_stats() -> int:
            global stats
            stats = aws_client.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
                Period=60,
                Statistics=["SampleCount", "Sum", "Maximum"],
            )
            datapoints = stats["Datapoints"]
            return len(datapoints)

        assert poll_condition(lambda: get_stats() >= 1, timeout=10)
        snapshot.match("get_metric_statistics", stats)

    @markers.aws.only_localstack
    def test_put_metric_data_gzip(self, aws_client, region_name):
        metric_name = "test-metric"
        namespace = "namespace"
        data = (
            "Action=PutMetricData&MetricData.member.1."
            "MetricName=%s&MetricData.member.1.Value=1&"
            "Namespace=%s&Version=2010-08-01" % (metric_name, namespace)
        )
        bytes_data = bytes(data, encoding="utf-8")
        encoded_data = gzip.compress(bytes_data)

        headers = mock_aws_request_headers(
            "cloudwatch",
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            region_name=region_name,
            internal=True,
        )
        authorization = mock_aws_request_headers(
            "monitoring", aws_access_key_id=TEST_AWS_ACCESS_KEY_ID, region_name=region_name
        )["Authorization"]

        headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Content-Length": len(encoded_data),
                "Content-Encoding": "GZIP",
                "User-Agent": "aws-sdk-nodejs/2.819.0 linux/v12.18.2 callback",
                "Authorization": authorization,
            }
        )
        url = config.external_service_url()
        request = Request(url, encoded_data, headers, method="POST")
        urlopen(request)

        rs = aws_client.cloudwatch.list_metrics(Namespace=namespace, MetricName=metric_name)
        assert 1 == len(rs["Metrics"])
        assert namespace == rs["Metrics"][0]["Namespace"]

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_put_metric_data_validation(self, aws_client):
        namespace = f"ns-{short_uid()}"
        utc_now = datetime.utcnow().replace(tzinfo=timezone.utc)

        # test invalid due to having both Values and Value
        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": "mymetric",
                        "Timestamp": utc_now,
                        "Value": 1.5,
                        "Values": [1.0, 10.0],
                        "Unit": "Count",
                    }
                ],
            )
        err = ex.value.response["Error"]
        assert err["Code"] == "InvalidParameterCombination"
        assert (
            err["Message"]
            == "The parameters MetricData.member.1.Value and MetricData.member.1.Values are mutually exclusive and you have specified both."
        )

        # test invalid due to data can not have and values mismatched_counts
        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": "mymetric",
                        "Timestamp": utc_now,
                        "Values": [1.0, 10.0],
                        "Counts": [2, 4, 5],
                        "Unit": "Count",
                    }
                ],
            )
        err = ex.value.response["Error"]
        assert err["Code"] == "InvalidParameterValue"
        assert (
            err["Message"]
            == "The parameters MetricData.member.1.Values and MetricData.member.1.Counts must be of the same size."
        )

        # test invalid due to inserting both value and statistic values
        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": "mymetric",
                        "Timestamp": utc_now,
                        "Value": 1.5,
                        "StatisticValues": {
                            "SampleCount": 10,
                            "Sum": 55,
                            "Minimum": 1,
                            "Maximum": 10,
                        },
                        "Unit": "Count",
                    }
                ],
            )
        err = ex.value.response["Error"]
        assert err["Code"] == "InvalidParameterCombination"
        assert (
            err["Message"]
            == "The parameters MetricData.member.1.Value and MetricData.member.1.StatisticValues are mutually exclusive and you have specified both."
        )

        # For some strange reason the AWS implementation allows this
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "mymetric",
                    "Timestamp": utc_now,
                    "Values": [1.0, 10.0],
                    "StatisticValues": {
                        "SampleCount": 10,
                        "Sum": 55,
                        "Minimum": 1,
                        "Maximum": 10,
                    },
                    "Unit": "Count",
                }
            ],
        )

    @markers.aws.validated
    def test_get_metric_data(self, aws_client):
        namespace1 = f"test/{short_uid()}"
        namespace2 = f"test/{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1, MetricData=[dict(MetricName="someMetric", Value=23)]
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1, MetricData=[dict(MetricName="someMetric", Value=18)]
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace2, MetricData=[dict(MetricName="ug", Value=23)]
        )

        now = datetime.utcnow().replace(microsecond=0)
        start_time = now - timedelta(minutes=10)
        end_time = now + timedelta(minutes=5)

        def _get_metric_data_sum():
            # filtering metric data with current time interval
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "some",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace1,
                                "MetricName": "someMetric",
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    },
                    {
                        "Id": "part",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace2, "MetricName": "ug"},
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    },
                ],
                StartTime=start_time,
                EndTime=end_time,
            )
            assert 2 == len(response["MetricDataResults"])

            for data_metric in response["MetricDataResults"]:
                # TODO: there's an issue in the implementation of the service here.
                #  The returned timestamps should have the seconds set to 0
                if data_metric["Id"] == "some":
                    assert 41.0 == sum(
                        data_metric["Values"]
                    )  # might fall under different 60s "buckets"
                if data_metric["Id"] == "part":
                    assert 23.0 == sum(data_metric["Values"])

        # need to retry because the might most likely not be ingested immediately (it's fairly quick though)
        retry(_get_metric_data_sum, retries=10, sleep_before=2)

        # filtering metric data with current time interval
        response = aws_client.cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "some",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace1,
                            "MetricName": "someMetric",
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                },
                {
                    "Id": "part",
                    "MetricStat": {
                        "Metric": {"Namespace": namespace2, "MetricName": "ug"},
                        "Period": 60,
                        "Stat": "Sum",
                    },
                },
            ],
            StartTime=datetime.utcnow() + timedelta(hours=1),
            EndTime=datetime.utcnow() + timedelta(hours=2),
        )

        for data_metric in response["MetricDataResults"]:
            if data_metric["Id"] == "some":
                assert len(data_metric["Values"]) == 0
            if data_metric["Id"] == "part":
                assert len(data_metric["Values"]) == 0

    @markers.aws.validated
    def test_get_metric_data_for_multiple_metrics(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"test/{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "Value": 50,
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric2",
                    "Value": 25,
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric3",
                    "StatisticValues": {
                        "SampleCount": 10,
                        "Sum": 55,
                        "Minimum": 1,
                        "Maximum": 10,
                    },
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "result1",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace, "MetricName": "metric1"},
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    },
                    {
                        "Id": "result2",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace, "MetricName": "metric2"},
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    },
                    {
                        "Id": "result3",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace, "MetricName": "metric3"},
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    },
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

            assert len(response["MetricDataResults"][0]["Values"]) > 0
            snapshot.match("get_metric_data", response)

        retry(assert_results, retries=10, sleep_before=1)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "stat",
        ["Sum", "SampleCount", "Minimum", "Maximum", "Average"],
    )
    def test_get_metric_data_stats(self, aws_client, snapshot, stat):
        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"test/{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "Value": 11,
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "StatisticValues": {
                        "SampleCount": 10,
                        "Sum": 55,
                        "Minimum": 1,
                        "Maximum": 10,
                    },
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "result1",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace, "MetricName": "metric1"},
                            "Period": 60,
                            "Stat": stat,
                        },
                    }
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

            assert len(response["MetricDataResults"][0]["Values"]) > 0
            snapshot.match("get_metric_data", response)

        sleep_before = 2 if is_aws_cloud() else 0
        retry(assert_results, retries=10, sleep_before=sleep_before)

    @markers.aws.validated
    def test_get_metric_data_with_dimensions(self, aws_client, snapshot):
        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"test/{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "Value": 11,
                    "Unit": "Seconds",
                    "Dimensions": [{"Name": "InstanceId", "Value": "one"}],
                    "Timestamp": utc_now,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "Value": 11,
                    "Unit": "Seconds",
                    "Dimensions": [{"Name": "InstanceId", "Value": "two"}],
                    "Timestamp": utc_now,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "metric1",
                    "StatisticValues": {
                        "SampleCount": 10,
                        "Sum": 55,
                        "Minimum": 1,
                        "Maximum": 10,
                    },
                    "Unit": "Seconds",
                    "Timestamp": utc_now,
                }
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "result1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": "metric1",
                                "Dimensions": [
                                    {"Name": "InstanceId", "Value": "one"},
                                ],
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

            assert len(response["MetricDataResults"][0]["Values"]) > 0
            snapshot.match("get_metric_data", response)

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0
        retry(assert_results, retries=retries, sleep_before=sleep_before)

    @markers.aws.only_localstack
    # this feature was a customer request and added with https://github.com/localstack/localstack/pull/3535
    def test_raw_metric_data(self, aws_client, region_name):
        """
        tests internal endpoint at "/_aws/cloudwatch/metrics/raw"
        """
        namespace1 = f"test/{short_uid()}"
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1, MetricData=[dict(MetricName="someMetric", Value=23)]
        )
        # the new v2 provider doesn't need the headers, will return results for all accounts/regions
        headers = mock_aws_request_headers(
            "cloudwatch", aws_access_key_id=TEST_AWS_ACCESS_KEY_ID, region_name=region_name
        )
        url = f"{config.external_service_url()}{PATH_GET_RAW_METRICS}"
        result = requests.get(url, headers=headers)
        assert 200 == result.status_code
        result = json.loads(to_str(result.content))
        metrics = result["metrics"]
        metrics_with_ns = [m for m in metrics if m.get("ns") == namespace1]
        assert len(metrics_with_ns) == 1

    @markers.aws.validated
    def test_multiple_dimensions(self, aws_client):
        namespaces = [
            f"ns1-{short_uid()}",
            f"ns2-{short_uid()}",
            f"ns3-{short_uid()}",
        ]
        num_dimensions = 2
        for ns in namespaces:
            for i in range(3):
                rs = aws_client.cloudwatch.put_metric_data(
                    Namespace=ns,
                    MetricData=[
                        {
                            "MetricName": "someMetric",
                            "Value": 123,
                            "Dimensions": [
                                {
                                    "Name": "foo",
                                    "Value": f"bar-{i % num_dimensions}",
                                }
                            ],
                        }
                    ],
                )
                assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        def _check_metrics():
            rs = aws_client.cloudwatch.get_paginator("list_metrics").paginate().build_full_result()
            metrics = [m for m in rs["Metrics"] if m.get("Namespace") in namespaces]
            assert metrics
            assert len(metrics) == len(namespaces) * num_dimensions

        retry(_check_metrics, sleep=2, retries=10, sleep_before=2)

    @markers.aws.validated
    def test_describe_alarms_converts_date_format_correctly(self, aws_client, cleanups):
        alarm_name = f"a-{short_uid()}:test"
        metric_name = f"test-metric-{short_uid()}"
        namespace = f"test-ns-{short_uid()}"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            Period=60,
            Statistic="Sum",
            Threshold=30,
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        result = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        alarm = result["MetricAlarms"][0]
        assert isinstance(alarm["AlarmConfigurationUpdatedTimestamp"], datetime)
        assert isinstance(alarm["StateUpdatedTimestamp"], datetime)

    @markers.aws.validated
    def test_put_composite_alarm_describe_alarms(self, aws_client, cleanups):
        composite_alarm_name = f"composite-a-{short_uid()}"
        alarm_name = f"a-{short_uid()}"
        metric_name = "something"
        namespace = f"test-ns-{short_uid()}"
        alarm_rule = f'ALARM("{alarm_name}")'
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            Period=60,
            Statistic="Sum",
            Threshold=30,
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        aws_client.cloudwatch.put_composite_alarm(
            AlarmName=composite_alarm_name,
            AlarmRule=alarm_rule,
        )
        cleanups.append(
            lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[composite_alarm_name])
        )
        result = aws_client.cloudwatch.describe_alarms(
            AlarmNames=[composite_alarm_name], AlarmTypes=["CompositeAlarm"]
        )
        alarm = result["CompositeAlarms"][0]
        assert alarm["AlarmName"] == composite_alarm_name
        assert alarm["AlarmRule"] == alarm_rule

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider,
        paths=["$..MetricAlarms..AlarmDescription", "$..MetricAlarms..StateTransitionedTimestamp"],
    )
    def test_store_tags(self, aws_client, cleanups, snapshot):
        alarm_name = f"a-{short_uid()}"
        metric_name = "store_tags"
        namespace = f"test-ns-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        put_metric_alarm = aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName=metric_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            Period=60,
            Statistic="Sum",
            Threshold=30,
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        snapshot.match("put_metric_alarm", put_metric_alarm)

        describe_alarms = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe_alarms", describe_alarms)
        alarm = describe_alarms["MetricAlarms"][0]
        alarm_arn = alarm["AlarmArn"]
        list_tags_for_resource = aws_client.cloudwatch.list_tags_for_resource(ResourceARN=alarm_arn)
        snapshot.match("list_tags_for_resource_empty ", list_tags_for_resource)

        # add tags
        tags = [{"Key": "tag1", "Value": "foo"}, {"Key": "tag2", "Value": "bar"}]
        response = aws_client.cloudwatch.tag_resource(ResourceARN=alarm_arn, Tags=tags)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        list_tags_for_resource = aws_client.cloudwatch.list_tags_for_resource(ResourceARN=alarm_arn)
        snapshot.match("list_tags_for_resource", list_tags_for_resource)
        response = aws_client.cloudwatch.untag_resource(ResourceARN=alarm_arn, TagKeys=["tag1"])
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        list_tags_for_resource_post_untag = aws_client.cloudwatch.list_tags_for_resource(
            ResourceARN=alarm_arn
        )
        snapshot.match("list_tags_for_resource_post_untag", list_tags_for_resource_post_untag)

    @markers.aws.validated
    def test_list_metrics_uniqueness(self, aws_client):
        """
        This can take quite a while on AWS unfortunately
        From the AWS docs:
            After you create a metric, allow up to 15 minutes for the metric to appear.
            To see metric statistics sooner, use GetMetricData or GetMetricStatistics.
        """
        # create metrics with same namespace and dimensions but different metric names
        namespace = f"test/{short_uid()}"
        sleep_seconds = 10 if is_aws_cloud() else 1
        retries = 100 if is_aws_cloud() else 10
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "MemoryUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 30,
                }
            ],
        )

        # duplicating existing metric
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "MemoryUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )

        def _count_single_metrics():
            results = aws_client.cloudwatch.list_metrics(Namespace=namespace)["Metrics"]
            assert len(results) == 2

        # asserting only unique values are returned
        retry(_count_single_metrics, retries=retries, sleep_before=sleep_seconds)

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "DiskReadOps",
                    "StatisticValues": {
                        "Maximum": 1.0,
                        "Minimum": 1.0,
                        "SampleCount": 1.0,
                        "Sum": 1.0,
                    },
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                }
            ],
        )

        def _count_aggregated_metrics():
            results = aws_client.cloudwatch.list_metrics(Namespace=namespace)["Metrics"]
            assert len(results) == 3

        retry(_count_aggregated_metrics, retries=retries, sleep_before=sleep_seconds)

    @markers.aws.validated
    def test_list_metrics_with_filters(self, aws_client):
        namespace = f"test/{short_uid()}"
        sleep_seconds = 10 if is_aws_cloud() else 1
        retries = 100 if is_aws_cloud() else 10
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Value": 15,
                }
            ],
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "MemoryUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "one"}],
                    "Value": 30,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "DiskReadOps",
                    "Dimensions": [{"Name": "InstanceId", "Value": "two"}],
                    "Value": 15,
                }
            ],
        )

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "DiskWriteOps",
                    "Dimensions": [{"Name": "InstanceId", "Value": "two"}],
                    "StatisticValues": {
                        "Maximum": 1.0,
                        "Minimum": 1.0,
                        "SampleCount": 1.0,
                        "Sum": 1.0,
                    },
                }
            ],
        )

        def _count_all_metrics_in_namespace():
            results = aws_client.cloudwatch.list_metrics(Namespace=namespace)["Metrics"]
            assert len(results) == 4

        retry(_count_all_metrics_in_namespace, retries=retries, sleep_before=sleep_seconds)

        def _count_specific_metric_in_namespace():
            results = aws_client.cloudwatch.list_metrics(
                Namespace=namespace, MetricName="CPUUtilization"
            )["Metrics"]
            assert len(results) == 1

        retry(_count_specific_metric_in_namespace, retries=retries, sleep_before=sleep_seconds)

        def _count_metrics_in_namespace_with_dimension():
            results = aws_client.cloudwatch.list_metrics(
                Namespace=namespace, Dimensions=[{"Name": "InstanceId"}]
            )["Metrics"]
            assert len(results) == 3

        retry(
            _count_metrics_in_namespace_with_dimension, retries=retries, sleep_before=sleep_seconds
        )

        def _count_metrics_in_namespace_with_dimension_value():
            results = aws_client.cloudwatch.list_metrics(
                Namespace=namespace, Dimensions=[{"Name": "InstanceId", "Value": "two"}]
            )["Metrics"]
            assert len(results) == 2

        retry(
            _count_metrics_in_namespace_with_dimension_value,
            retries=retries,
            sleep_before=sleep_seconds,
        )

    @markers.aws.validated
    def test_put_metric_alarm_escape_character(self, cleanups, aws_client):
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName="cpu-mon",
            AlarmDescription="<",
            MetricName="CPUUtilization-2",
            Namespace="AWS/EC2",
            Statistic="Sum",
            Period=600,
            Threshold=1,
            ComparisonOperator="GreaterThanThreshold",
            EvaluationPeriods=1,
            AlarmActions=["arn:aws:sns:us-east-1:111122223333:MyTopic"],
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=["cpu-mon"]))

        result = aws_client.cloudwatch.describe_alarms(AlarmNames=["cpu-mon"])
        assert result.get("MetricAlarms")[0]["AlarmDescription"] == "<"

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..MetricAlarms..StateTransitionedTimestamp"]
    )
    def test_set_alarm(self, sns_create_topic, sqs_create_queue, aws_client, cleanups, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        # create topics for state 'ALARM' and 'OK'
        topic_name_alarm = f"topic-{short_uid()}"
        topic_name_ok = f"topic-{short_uid()}"

        sns_topic_alarm = sns_create_topic(Name=topic_name_alarm)
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        sns_topic_ok = sns_create_topic(Name=topic_name_ok)
        topic_arn_ok = sns_topic_ok["TopicArn"]
        snapshot.add_transformer(snapshot.transform.regex(topic_name_alarm, "<topic_alarm>"))
        snapshot.add_transformer(snapshot.transform.regex(topic_arn_ok, "<topic_ok>"))

        # create queues for 'ALARM' and 'OK' (will receive sns messages)
        uid = short_uid()
        queue_url_alarm = sqs_create_queue(QueueName=f"AlarmQueue-{uid}")
        queue_url_ok = sqs_create_queue(QueueName=f"OKQueue-{uid}")

        arn_queue_alarm = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url_alarm, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        arn_queue_ok = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url_ok, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url_alarm,
            Attributes={"Policy": get_sqs_policy(arn_queue_alarm, topic_arn_alarm)},
        )
        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url_ok, Attributes={"Policy": get_sqs_policy(arn_queue_ok, topic_arn_ok)}
        )

        alarm_name = "test-alarm"
        alarm_description = "Test Alarm when CPU exceeds 50 percent"

        expected_trigger = {
            "MetricName": "CPUUtilization-3",
            "Namespace": "AWS/EC2",
            "Unit": "Percent",
            "Period": 300,
            "EvaluationPeriods": 2,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 50.0,
            "TreatMissingData": "ignore",
            "EvaluateLowSampleCountPercentile": "",
            "Dimensions": [{"value": "i-0317828c84edbe100", "name": "InstanceId"}],
            "StatisticType": "Statistic",
            "Statistic": "AVERAGE",
        }
        # subscribe to SQS
        subscription_alarm = aws_client.sns.subscribe(
            TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=arn_queue_alarm
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(
                SubscriptionArn=subscription_alarm["SubscriptionArn"]
            )
        )
        subscription_ok = aws_client.sns.subscribe(
            TopicArn=topic_arn_ok, Protocol="sqs", Endpoint=arn_queue_ok
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription_ok["SubscriptionArn"])
        )

        # create alarm with actions for "OK" and "ALARM"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription=alarm_description,
            MetricName=expected_trigger["MetricName"],
            Namespace=expected_trigger["Namespace"],
            ActionsEnabled=True,
            Period=expected_trigger["Period"],
            Threshold=expected_trigger["Threshold"],
            Dimensions=[{"Name": "InstanceId", "Value": "i-0317828c84edbe100"}],
            Unit=expected_trigger["Unit"],
            Statistic=expected_trigger["Statistic"].capitalize(),
            OKActions=[topic_arn_ok],
            AlarmActions=[topic_arn_alarm],
            EvaluationPeriods=expected_trigger["EvaluationPeriods"],
            ComparisonOperator=expected_trigger["ComparisonOperator"],
            TreatMissingData=expected_trigger["TreatMissingData"],
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))

        # trigger alarm
        state_value = "ALARM"
        state_reason = "testing alarm"
        aws_client.cloudwatch.set_alarm_state(
            AlarmName=alarm_name, StateReason=state_reason, StateValue=state_value
        )

        retry(
            check_message,
            retries=PUBLICATION_RETRIES,
            sleep_before=1,
            sqs_client=aws_client.sqs,
            expected_queue_url=queue_url_alarm,
            expected_topic_arn=topic_arn_alarm,
            expected_new=state_value,
            expected_reason=state_reason,
            alarm_name=alarm_name,
            alarm_description=alarm_description,
            expected_trigger=expected_trigger,
        )
        describe_alarm = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("triggered-alarm", describe_alarm)
        # trigger OK
        state_value = "OK"
        state_reason = "resetting alarm"
        aws_client.cloudwatch.set_alarm_state(
            AlarmName=alarm_name, StateReason=state_reason, StateValue=state_value
        )

        retry(
            check_message,
            retries=PUBLICATION_RETRIES,
            sleep_before=1,
            sqs_client=aws_client.sqs,
            expected_queue_url=queue_url_ok,
            expected_topic_arn=topic_arn_ok,
            expected_new=state_value,
            expected_reason=state_reason,
            alarm_name=alarm_name,
            alarm_description=alarm_description,
            expected_trigger=expected_trigger,
        )
        describe_alarm = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("reset-alarm", describe_alarm)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..AlarmHistoryItems..HistoryData.newState.stateReason",
            "$..AlarmHistoryItems..HistoryData.newState.stateReasonData.evaluatedDatapoints",
            "$..NewStateReason",
            "$..describe-alarms-for-metric..StateReason",  # reason contains datapoint + date
            "$..describe-alarms-for-metric..StateReasonData.evaluatedDatapoints",
        ]
    )
    @pytest.mark.skipif(
        condition=is_old_provider(), reason="DescribeAlarmHistory is not implemented"
    )
    def test_put_metric_alarm(
        self, sns_create_topic, sqs_create_queue, snapshot, aws_client, cleanups
    ):
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]

        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        snapshot.add_transformer(
            snapshot.transform.regex(topic_arn_alarm.split(":")[-1], "<topic_arn>"), priority=2
        )
        snapshot.add_transformer(
            # regex to transform date-pattern, e.g. (03/01/24 11:36:00)
            snapshot.transform.regex(
                r"\(\d{2}\/\d{2}\/\d{2}\ \d{2}:\d{2}:\d{2}\)", "(MM/DD/YY HH:MM:SS)"
            )
        )
        # as we add metrics, we use a unique namespace to ensure the test runs on AWS
        namespace = f"test-nsp-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(namespace, "<metric-namespace>"))

        sqs_queue = sqs_create_queue()
        arn_queue = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        # required for AWS:
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue,
            Attributes={"Policy": get_sqs_policy(arn_queue, topic_arn_alarm)},
        )
        metric_name = "my-metric1"
        dimension = [{"Name": "InstanceId", "Value": "abc"}]
        alarm_name = f"test-alarm-{short_uid()}"

        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=arn_queue
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        )
        data = [
            {
                "MetricName": metric_name,
                "Dimensions": dimension,
                "Value": 21,
                "Timestamp": datetime.utcnow().replace(tzinfo=timezone.utc),
                "Unit": "Seconds",
            },
            {
                "MetricName": metric_name,
                "Dimensions": dimension,
                "Value": 22,
                "Timestamp": datetime.utcnow().replace(tzinfo=timezone.utc),
                "Unit": "Seconds",
            },
        ]

        # create alarm with action for "ALARM"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription="testing cloudwatch alarms",
            MetricName=metric_name,
            Namespace=namespace,
            ActionsEnabled=True,
            Period=30,
            Threshold=2,
            Dimensions=dimension,
            Unit="Seconds",
            Statistic="Average",
            OKActions=[topic_arn_alarm],
            AlarmActions=[topic_arn_alarm],
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
            # notBreaching had some downsides, as depending on the alarm evaluation interval it would first go into OK
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe-alarm", response)

        aws_client.cloudwatch.put_metric_data(Namespace=namespace, MetricData=data)
        retry(
            _sqs_messages_snapshot,
            retries=60,
            sleep=3 if is_aws_cloud() else 1,
            sleep_before=5 if is_aws_cloud() else 0,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            snapshot=snapshot,
            identifier="alarm-triggered",
        )

        # describe alarm history
        history = aws_client.cloudwatch.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate"
        )
        snapshot.match("describe-alarm-history", history)

        # describe alarms for metric
        alarms = aws_client.cloudwatch.describe_alarms_for_metric(
            MetricName=metric_name,
            Namespace=namespace,
            Dimensions=dimension,
            Statistic="Average",
        )
        snapshot.match("describe-alarms-for-metric", alarms)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..MetricAlarms..StateTransitionedTimestamp",
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..MetricAlarms..StateReasonData.evaluatedDatapoints",
            "$..MetricAlarms..StateReasonData.startDate",
        ]
    )
    def test_breaching_alarm_actions(
        self, sns_create_topic, sqs_create_queue, snapshot, aws_client, cleanups
    ):
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        snapshot.add_transformer(
            snapshot.transform.regex(topic_arn_alarm.split(":")[-1], "<topic_arn>"), priority=2
        )

        sqs_queue = sqs_create_queue()
        arn_queue = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        # required for AWS:
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue,
            Attributes={"Policy": get_sqs_policy(arn_queue, topic_arn_alarm)},
        )
        metric_name = "my-metric101"
        dimension = [{"Name": "InstanceId", "Value": "abc"}]
        namespace = "test/breaching-alarm"
        alarm_name = f"test-alarm-{short_uid()}"

        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=arn_queue
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        )

        snapshot.match("cloudwatch_sns_subscription", subscription)
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription="testing cloudwatch alarms",
            MetricName=metric_name,
            Namespace=namespace,
            Period=10,
            Threshold=2,
            Dimensions=dimension,
            Unit="Seconds",
            Statistic="Average",
            OKActions=[topic_arn_alarm],
            AlarmActions=[topic_arn_alarm],
            EvaluationPeriods=2,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="breaching",
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        assert response["MetricAlarms"][0]["ActionsEnabled"]

        retry(
            _sqs_messages_snapshot,
            retries=80,
            sleep=3.0,
            sleep_before=5,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            snapshot=snapshot,
            identifier="alarm-1",
        )
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("alarm-1-describe", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider, paths=["$..MetricAlarms..StateTransitionedTimestamp"]
    )
    def test_enable_disable_alarm_actions(
        self, sns_create_topic, sqs_create_queue, snapshot, aws_client, cleanups
    ):
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        snapshot.add_transformer(
            snapshot.transform.regex(topic_arn_alarm.split(":")[-1], "<topic_arn>"), priority=2
        )

        sqs_queue = sqs_create_queue()
        arn_queue = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        # required for AWS:
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue,
            Attributes={"Policy": get_sqs_policy(arn_queue, topic_arn_alarm)},
        )
        metric_name = "my-metric101"
        dimension = [{"Name": "InstanceId", "Value": "abc"}]
        namespace = f"test/enable-{short_uid()}"
        alarm_name = f"test-alarm-{short_uid()}"

        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=arn_queue
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        )
        snapshot.match("cloudwatch_sns_subscription", subscription)
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription="testing cloudwatch alarms",
            MetricName=metric_name,
            Namespace=namespace,
            Period=10,
            Threshold=2,
            Dimensions=dimension,
            Unit="Seconds",
            Statistic="Average",
            OKActions=[topic_arn_alarm],
            AlarmActions=[topic_arn_alarm],
            EvaluationPeriods=2,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        assert response["MetricAlarms"][0]["ActionsEnabled"]
        snapshot.match("describe_alarm", response)

        aws_client.cloudwatch.set_alarm_state(
            AlarmName=alarm_name, StateValue="ALARM", StateReason="testing alarm"
        )
        retry(
            _sqs_messages_snapshot,
            retries=80,
            sleep=3.0,
            sleep_before=5,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            snapshot=snapshot,
            identifier="alarm-state",
        )
        describe_alarm = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("alarm-state-describe", describe_alarm)

        # disable alarm action
        aws_client.cloudwatch.disable_alarm_actions(AlarmNames=[alarm_name])
        aws_client.cloudwatch.set_alarm_state(
            AlarmName=alarm_name, StateValue="OK", StateReason="testing OK state"
        )

        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe_alarm_disabled", response)
        assert response["MetricAlarms"][0]["StateValue"] == "OK"
        assert not response["MetricAlarms"][0]["ActionsEnabled"]
        retry(
            _check_alarm_triggered,
            retries=80,
            sleep=3.0,
            sleep_before=5,
            expected_state="OK",
            alarm_name=alarm_name,
            cloudwatch_client=aws_client.cloudwatch,
            snapshot=snapshot,
            identifier="ok-state-action-disabled",
        )

        # enable alarm action
        aws_client.cloudwatch.enable_alarm_actions(AlarmNames=[alarm_name])
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe_alarm_enabled", response)
        assert response["MetricAlarms"][0]["ActionsEnabled"]

    @markers.aws.validated
    def test_aws_sqs_metrics_created(self, sqs_create_queue, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        sqs_url = sqs_create_queue()
        sqs_arn = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        queue_name = arns.sqs_queue_name(sqs_arn)
        # this should trigger the metric "NumberOfEmptyReceives"
        aws_client.sqs.receive_message(QueueUrl=sqs_url)

        aws_client.sqs.send_message(QueueUrl=sqs_url, MessageBody="Hello")
        dimensions = [{"Name": "QueueName", "Value": queue_name}]

        metric_default = {
            "MetricStat": {
                "Metric": {
                    "Namespace": "AWS/SQS",
                    "Dimensions": dimensions,
                },
                "Period": 60,
                "Stat": "Sum",
            },
        }
        sent = {"Id": "sent"}
        sent.update(copy.deepcopy(metric_default))
        sent["MetricStat"]["Metric"]["MetricName"] = "NumberOfMessagesSent"

        sent_size = {"Id": "sent_size"}
        sent_size.update(copy.deepcopy(metric_default))
        sent_size["MetricStat"]["Metric"]["MetricName"] = "SentMessageSize"

        empty = {"Id": "empty_receives"}
        empty.update(copy.deepcopy(metric_default))
        empty["MetricStat"]["Metric"]["MetricName"] = "NumberOfEmptyReceives"

        def contains_sent_messages_metrics() -> int:
            res = aws_client.cloudwatch.list_metrics(Dimensions=dimensions)
            metrics = [metric["MetricName"] for metric in res["Metrics"]]
            if all(
                m in metrics
                for m in ["NumberOfMessagesSent", "SentMessageSize", "NumberOfEmptyReceives"]
            ):
                res = aws_client.cloudwatch.get_metric_data(
                    MetricDataQueries=[sent, sent_size, empty],
                    StartTime=datetime.utcnow() - timedelta(hours=1),
                    EndTime=datetime.utcnow(),
                )
                # add check for values, because AWS is sometimes a bit slower to fill those values up...
                if (
                    res["MetricDataResults"][0]["Values"]
                    and res["MetricDataResults"][1]["Values"]
                    and res["MetricDataResults"][2]["Values"]
                ):
                    return True
            return False

        assert poll_condition(lambda: contains_sent_messages_metrics(), interval=1, timeout=120)

        response = aws_client.cloudwatch.get_metric_data(
            MetricDataQueries=[sent, sent_size, empty],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )

        snapshot.match("get_metric_data", response)

        # receive + delete message
        sqs_messages = aws_client.sqs.receive_message(QueueUrl=sqs_url)["Messages"]
        assert len(sqs_messages) == 1
        receipt_handle = sqs_messages[0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=sqs_url, ReceiptHandle=receipt_handle)

        msg_received = {"Id": "num_msg_received"}
        msg_received.update(copy.deepcopy(metric_default))
        msg_received["MetricStat"]["Metric"]["MetricName"] = "NumberOfMessagesReceived"

        msg_deleted = {"Id": "num_msg_deleted"}
        msg_deleted.update(copy.deepcopy(metric_default))
        msg_deleted["MetricStat"]["Metric"]["MetricName"] = "NumberOfMessagesDeleted"

        def contains_receive_delete_metrics() -> int:
            res = aws_client.cloudwatch.list_metrics(Dimensions=dimensions)
            metrics = [metric["MetricName"] for metric in res["Metrics"]]
            if all(m in metrics for m in ["NumberOfMessagesReceived", "NumberOfMessagesDeleted"]):
                res = aws_client.cloudwatch.get_metric_data(
                    MetricDataQueries=[msg_received, msg_deleted],
                    StartTime=datetime.utcnow() - timedelta(hours=1),
                    EndTime=datetime.utcnow(),
                )
                # add check for values, because AWS is sometimes a bit slower to fill those values up...
                if res["MetricDataResults"][0]["Values"] and res["MetricDataResults"][1]["Values"]:
                    return True
            return False

        assert poll_condition(lambda: contains_receive_delete_metrics(), interval=1, timeout=120)

        response = aws_client.cloudwatch.get_metric_data(
            MetricDataQueries=[msg_received, msg_deleted],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )

        snapshot.match("get_metric_data_2", response)

    @markers.aws.validated
    @pytest.mark.skipif(condition=is_old_provider(), reason="Old provider is not raising exception")
    def test_invalid_dashboard_name(self, aws_client, region_name, snapshot):
        dashboard_name = f"test-{short_uid()}:invalid"
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 6,
                    "properties": {
                        "metrics": [["AWS/EC2", "CPUUtilization", "InstanceId", "i-12345678"]],
                        "region": region_name,
                        "view": "timeSeries",
                        "stacked": False,
                    },
                }
            ]
        }

        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.put_dashboard(
                DashboardName=dashboard_name, DashboardBody=json.dumps(dashboard_body)
            )

        snapshot.match("error-invalid-dashboardname", ex.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..DashboardArn",  # ARN has a typo in moto
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..DashboardEntries..Size",  # need to be skipped because size changes if the region name length is longer
        ]
    )
    def test_dashboard_lifecycle(self, aws_client, region_name, snapshot):
        dashboard_name = f"test-{short_uid()}"
        dashboard_body = {
            "widgets": [
                {
                    "type": "metric",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 6,
                    "properties": {
                        "metrics": [["AWS/EC2", "CPUUtilization", "InstanceId", "i-12345678"]],
                        "region": region_name,
                        "view": "timeSeries",
                        "stacked": False,
                    },
                }
            ]
        }
        aws_client.cloudwatch.put_dashboard(
            DashboardName=dashboard_name, DashboardBody=json.dumps(dashboard_body)
        )
        response = aws_client.cloudwatch.get_dashboard(DashboardName=dashboard_name)
        snapshot.add_transformer(snapshot.transform.key_value("DashboardName"))
        snapshot.match("get_dashboard", response)

        dashboards_list = aws_client.cloudwatch.list_dashboards()
        snapshot.match("list_dashboards", dashboards_list)

        # assert prefix filtering working
        dashboards_list = aws_client.cloudwatch.list_dashboards(DashboardNamePrefix="no-valid")
        snapshot.match("list_dashboards_prefix_empty", dashboards_list)
        dashboards_list = aws_client.cloudwatch.list_dashboards(DashboardNamePrefix="test")
        snapshot.match("list_dashboards_prefix", dashboards_list)

        aws_client.cloudwatch.delete_dashboards(DashboardNames=[dashboard_name])
        dashboards_list = aws_client.cloudwatch.list_dashboards()
        snapshot.match("list_dashboards_empty", dashboards_list)

    @markers.aws.validated
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Operations not supported")
    def test_create_metric_stream(
        self,
        aws_client,
        firehose_create_delivery_stream,
        s3_create_bucket,
        create_role_with_policy,
        snapshot,
    ):
        bucket_name = f"test-bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)

        _, subscription_role_arn = create_role_with_policy(
            "Allow",
            "s3:*",
            json.dumps(
                {
                    "Statement": {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {"Service": "firehose.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                }
            ),
            "*",
        )

        if is_aws_cloud():
            time.sleep(15)

        stream_name = f"MyStream-{short_uid()}"
        stream_arn = firehose_create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": subscription_role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket_name}",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            },
        )["DeliveryStreamARN"]

        _, role_arn = create_role_with_policy(
            "Allow",
            "firehose:*",
            json.dumps(
                {
                    "Statement": {
                        "Sid": "",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudwatch.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                }
            ),
            stream_arn,
        )

        if is_aws_cloud():
            time.sleep(15)

        metric_stream_name = f"MyMetricStream-{short_uid()}"
        response_create = aws_client.cloudwatch.put_metric_stream(
            Name=metric_stream_name,
            FirehoseArn=stream_arn,
            RoleArn=role_arn,
            OutputFormat="json",
        )
        snapshot.add_transformer(snapshot.transform.key_value("Name"))
        snapshot.add_transformer(snapshot.transform.key_value("FirehoseArn"))
        snapshot.add_transformer(snapshot.transform.key_value("RoleArn"))

        snapshot.match("create_metric_stream", response_create)

        get_response = aws_client.cloudwatch.get_metric_stream(Name=metric_stream_name)
        snapshot.match("get_metric_stream", get_response)

        response_list = aws_client.cloudwatch.list_metric_streams()
        metric_streams = response_list.get("Entries", [])
        metric_streams_names = [metric_stream["Name"] for metric_stream in metric_streams]
        assert metric_stream_name in metric_streams_names

        start_response = aws_client.cloudwatch.start_metric_streams(Names=[metric_stream_name])
        snapshot.match("start_metric_stream", start_response)

        stop_response = aws_client.cloudwatch.stop_metric_streams(Names=[metric_stream_name])
        snapshot.match("stop_metric_stream", stop_response)

        response_delete = aws_client.cloudwatch.delete_metric_stream(Name=metric_stream_name)
        snapshot.match("delete_metric_stream", response_delete)
        response_list = aws_client.cloudwatch.list_metric_streams()
        metric_streams = response_list.get("Entries", [])
        metric_streams_names = [metric_stream["Name"] for metric_stream in metric_streams]
        assert metric_stream_name not in metric_streams_names

    @markers.aws.validated
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Operations not supported")
    def test_insight_rule(self, aws_client, snapshot):
        insight_rule_name = f"MyInsightRule-{short_uid()}"
        response_create = aws_client.cloudwatch.put_insight_rule(
            RuleName=insight_rule_name,
            RuleState="ENABLED",
            RuleDefinition=json.dumps(
                {
                    "Schema": {"Name": "CloudWatchLogRule", "Version": 1},
                    "LogGroupNames": ["API-Gateway-Access-Logs*"],
                    "LogFormat": "CLF",
                    "Fields": {"4": "IpAddress", "7": "StatusCode"},
                    "Contribution": {
                        "Keys": ["IpAddress"],
                        "Filters": [{"Match": "StatusCode", "EqualTo": 200}],
                    },
                    "AggregateOn": "Count",
                }
            ),
        )
        snapshot.add_transformer(snapshot.transform.key_value("Name"))
        snapshot.match("create_insight_rule", response_create)

        response_describe = aws_client.cloudwatch.describe_insight_rules()
        snapshot.match("describe_insight_rule", response_describe)

        response_disable = aws_client.cloudwatch.disable_insight_rules(
            RuleNames=[insight_rule_name]
        )
        snapshot.match("disable_insight_rule", response_disable)

        response_enable = aws_client.cloudwatch.enable_insight_rules(RuleNames=[insight_rule_name])
        snapshot.match("enable_insight_rule", response_enable)

        insight_rule_report = aws_client.cloudwatch.get_insight_rule_report(
            RuleName=insight_rule_name,
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
            Period=300,
            MaxContributorCount=10,
            Metrics=["UniqueContributors"],
        )
        snapshot.match("get_insight_rule_report", insight_rule_report)

        response_list = aws_client.cloudwatch.describe_insight_rules()
        insight_rules_names = [
            insight_rule["Name"] for insight_rule in response_list["InsightRules"]
        ]
        assert insight_rule_name in insight_rules_names

        response_delete = aws_client.cloudwatch.delete_insight_rules(RuleNames=[insight_rule_name])
        snapshot.match("delete_insight_rule", response_delete)

    @markers.aws.validated
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Operations not supported")
    def test_anomaly_detector_lifecycle(self, aws_client, snapshot):
        namespace = "MyNamespace"
        metric_name = "MyMetric"

        response_create = aws_client.cloudwatch.put_anomaly_detector(
            MetricName=metric_name,
            Namespace=namespace,
            Stat="Sum",
            Configuration={},
            Dimensions=[{"Name": "DimensionName", "Value": "DimensionValue"}],
        )
        snapshot.match("create_anomaly_detector", response_create)

        response_list = aws_client.cloudwatch.describe_anomaly_detectors()
        snapshot.match("describe_anomaly_detector", response_list)

        response_delete = aws_client.cloudwatch.delete_anomaly_detector(
            MetricName=metric_name,
            Namespace=namespace,
            Stat="Sum",
            Dimensions=[{"Name": "DimensionName", "Value": "DimensionValue"}],
        )
        snapshot.match("delete_anomaly_detector", response_delete)

    @markers.aws.validated
    @pytest.mark.skipif(condition=not is_aws_cloud(), reason="Operations not supported")
    def test_metric_widget(self, aws_client):
        metric_name = f"test-metric-{short_uid()}"
        namespace = f"ns-{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": datetime.utcnow().replace(tzinfo=timezone.utc),
                    "Values": [1.0, 10.0],
                    "Counts": [2, 4],
                    "Unit": "Count",
                }
            ],
        )

        response = aws_client.cloudwatch.get_metric_widget_image(
            MetricWidget=json.dumps(
                {
                    "metrics": [
                        [
                            namespace,
                            metric_name,
                            {"stat": "Sum", "id": "m1"},
                        ]
                    ],
                    "view": "timeSeries",
                    "stacked": False,
                    "region": "us-east-1",
                    "title": "test",
                    "width": 600,
                    "height": 400,
                    "start": "-PT3H",
                    "end": "P0D",
                }
            )
        )

        assert isinstance(response["MetricWidgetImage"], bytes)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="New test for v2 provider")
    def test_describe_minimal_metric_alarm(self, snapshot, aws_client, cleanups):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        alarm_name = f"a-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        name_space = f"n-sp-{short_uid()}"

        snapshot.add_transformer(TransformerUtility.key_value("MetricName"))
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            MetricName=metric_name,
            Namespace=name_space,
            EvaluationPeriods=1,
            Period=10,
            Statistic="Sum",
            ComparisonOperator="GreaterThanThreshold",
            Threshold=30,
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe_minimal_metric_alarm", response)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="New test for v2 provider")
    def test_set_alarm_invalid_input(self, aws_client, snapshot, cleanups):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        alarm_name = f"a-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        name_space = f"n-sp-{short_uid()}"

        snapshot.add_transformer(TransformerUtility.key_value("MetricName"))
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            MetricName=metric_name,
            Namespace=name_space,
            EvaluationPeriods=1,
            Period=10,
            Statistic="Sum",
            ComparisonOperator="GreaterThanThreshold",
            Threshold=30,
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.set_alarm_state(
                AlarmName=alarm_name, StateValue="INVALID", StateReason="test"
            )

        snapshot.match("error-invalid-state", ex.value.response)

        with pytest.raises(Exception) as ex:
            aws_client.cloudwatch.set_alarm_state(
                AlarmName=f"{alarm_name}-nonexistent", StateValue="OK", StateReason="test"
            )

        snapshot.match("error-resource-not-found", ex.value.response)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_get_metric_data_with_zero_and_labels(self, aws_client, snapshot):
        utc_now = datetime.now(tz=timezone.utc)

        namespace1 = f"test/{short_uid()}"
        # put metric data
        values = [0, 2, 4, 3.5, 7, 100]
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1,
            MetricData=[
                {"MetricName": "metric1", "Value": val, "Unit": "Seconds"} for val in values
            ],
        )
        # get_metric_data
        stats = ["Average", "Sum", "Minimum", "Maximum"]

        def _get_metric_data():
            return aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "result_" + stat,
                        "MetricStat": {
                            "Metric": {"Namespace": namespace1, "MetricName": "metric1"},
                            "Period": 60,
                            "Stat": stat,
                        },
                    }
                    for stat in stats
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

        def _match_results():
            response = _get_metric_data()
            # keep one assert to avoid storing incorrect values
            avg = [res for res in response["MetricDataResults"] if res["Id"] == "result_Average"][0]
            assert [int(val) for val in avg["Values"]] == [19]
            snapshot.match("get_metric_data_with_zero_and_labels", response)

        retry(_match_results, retries=10, sleep=1.0)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Datapoints..Unit"])
    def test_get_metric_statistics(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"test/{short_uid()}"

        for i in range(10):
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    dict(MetricName="metric", Value=i, Timestamp=utc_now + timedelta(seconds=1))
                ],
            )

        def assert_results():
            stats_responce = aws_client.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName="metric",
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
                Period=60,
                Statistics=["Average", "Sum", "Minimum", "Maximum", "SampleCount"],
            )

            assert len(stats_responce["Datapoints"]) == 1
            snapshot.match("get_metric_statistics", stats_responce)

        sleep_before = 2 if is_aws_cloud() else 0.0
        retry(assert_results, retries=10, sleep=1.0, sleep_before=sleep_before)

    @markers.aws.validated
    def test_list_metrics_pagination(self, aws_client):
        namespace = f"n-sp-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        max_metrics = 500  # max metrics per page according to AWS docs
        for i in range(0, max_metrics + 1):
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": f"{metric_name}-{i}",
                        "Value": 21,
                        "Unit": "Seconds",
                    }
                ],
            )

        def assert_metrics_count():
            response = aws_client.cloudwatch.list_metrics(Namespace=namespace)
            assert len(response["Metrics"]) == max_metrics and response.get("NextToken") is not None

        retry(assert_metrics_count, retries=10, sleep=1.0, sleep_before=1.0)

    @markers.aws.validated
    @pytest.mark.skipif(condition=is_old_provider(), reason="not supported by the old provider")
    def test_get_metric_data_pagination(self, aws_client):
        namespace = f"n-sp-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        max_data_points = 10  # default is 100,800 according to AWS docs
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        for i in range(0, max_data_points * 2):
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Timestamp": now + timedelta(seconds=(i * 60)),
                        "Value": i,
                        "Unit": "Seconds",
                    }
                ],
            )

        def assert_data_points_count():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=(max_data_points * 60 * 2)),
                MaxDatapoints=max_data_points,
            )
            assert (len(response["MetricDataResults"][0]["Values"]) == 10) and (
                response.get("NextToken") is not None
            )

        retry(assert_data_points_count, retries=10, sleep=1.0, sleep_before=2.0)

    @markers.aws.validated
    def test_put_metric_uses_utc(self, aws_client):
        namespace = f"n-sp-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        now_local = datetime.now(timezone(timedelta(hours=-5), "America/Cancun")).replace(
            tzinfo=None
        )  # Remove the tz info to avoid boto converting it to UTC
        now_utc = datetime.utcnow()
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 1,
                    "Unit": "Seconds",
                }
            ],
        )

        def assert_found_in_utc():
            response = aws_client.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                StartTime=now_local - timedelta(seconds=60),
                EndTime=now_local + timedelta(seconds=60),
                Period=60,
                Statistics=["Average"],
            )
            assert len(response["Datapoints"]) == 0

            response = aws_client.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                StartTime=now_utc - timedelta(seconds=60),
                EndTime=now_utc + timedelta(seconds=60),
                Period=60,
                Statistics=["Average"],
            )
            assert len(response["Datapoints"]) == 1

        retry(assert_found_in_utc, retries=10, sleep=1.0)

    @markers.aws.validated
    def test_default_ordering(self, aws_client):
        namespace = f"n-sp-{short_uid()}"
        metric_name = f"m-{short_uid()}"
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        for i in range(0, 10):
            aws_client.cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        "MetricName": metric_name,
                        "Timestamp": now + timedelta(seconds=(i * 60)),
                        "Value": i,
                        "Unit": "Seconds",
                    }
                ],
            )

        def assert_ordering():
            default_ordering = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=(10 * 60)),
                MaxDatapoints=10,
            )

            ascending_ordering = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=(10 * 60)),
                MaxDatapoints=10,
                ScanBy="TimestampAscending",
            )

            descening_ordering = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=(10 * 60)),
                MaxDatapoints=10,
                ScanBy="TimestampDescending",
            )

            default_ordering_datapoints = default_ordering["MetricDataResults"][0]["Timestamps"]
            ascending_ordering_datapoints = ascending_ordering["MetricDataResults"][0]["Timestamps"]
            descening_ordering_datapoints = descening_ordering["MetricDataResults"][0]["Timestamps"]

            # The default ordering is TimestampDescending
            assert default_ordering_datapoints == descening_ordering_datapoints
            assert default_ordering_datapoints == ascending_ordering_datapoints[::-1]

        retry(assert_ordering, retries=10, sleep=1.0)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_handle_different_units(self, aws_client, snapshot):
        namespace = f"n-sp-{short_uid()}"
        metric_name = "m-test"
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": now,
                    "Value": 1,
                    "Unit": "Seconds",
                },
                {
                    "MetricName": metric_name,
                    "Timestamp": now,
                    "Value": 5,
                    "Unit": "Count",
                },
                {
                    "MetricName": metric_name,
                    "Timestamp": now,
                    "Value": 10,
                },
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                StartTime=now - timedelta(seconds=60),
                EndTime=now + timedelta(seconds=60),
                Period=60,
                Statistics=["Average"],
            )
            assert len(response["Datapoints"]) == 3
            response["Datapoints"].sort(key=lambda x: x["Average"], reverse=True)
            snapshot.match("get_metric_statistics_with_different_units", response)

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0.0
        retry(assert_results, retries=retries, sleep=1.0, sleep_before=sleep_before)

    @markers.aws.validated
    def test_get_metric_data_with_different_units(self, aws_client, snapshot):
        namespace = f"n-sp-{short_uid()}"
        metric_name = "m-test"
        now = datetime.utcnow().replace(tzinfo=timezone.utc)
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Timestamp": now,
                    "Value": 1,
                    "Unit": "Seconds",
                },
                {
                    "MetricName": metric_name,
                    "Timestamp": now,
                    "Value": 1,
                    "Unit": "Count",
                },
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                            "Unit": "Seconds",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=60),
                MaxDatapoints=10,
            )
            snapshot.match("get_metric_data_with_different_units", response)

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0.0
        retry(assert_results, retries=retries, sleep=1.0, sleep_before=sleep_before)

    base_metric_data = [
        {
            "MetricName": "<metric_name>",
            "Timestamp": "<now>",
            "Value": 60000,
            "Unit": "Milliseconds",
        },
        {
            "MetricName": "<metric_name>",
            "Timestamp": "<now>",
            "Value": 60,
            "Unit": "Seconds",
        },
    ]
    count_metric = {
        "MetricName": "<metric_name>",
        "Timestamp": "<now>",
        "Value": 5,
        "Unit": "Count",
    }

    @pytest.mark.parametrize(
        "metric_data",
        [
            base_metric_data,
            base_metric_data + base_metric_data,
            base_metric_data + base_metric_data + [count_metric],
        ],
    )
    @markers.aws.needs_fixing
    @pytest.mark.skip(reason="Not supported in either provider, needs to be fixed in new one")
    def test_get_metric_data_different_units_no_unit_in_query(
        self, aws_client, snapshot, metric_data
    ):
        # From the docs:
        """
        In a Get operation, if you omit Unit then all data that was collected with any unit is returned, along with the
        corresponding units that were specified when the data was reported to CloudWatch. If you specify a unit, the
        operation returns only data that was collected with that unit specified. If you specify a unit that does not
        match the data collected, the results of the operation are null. CloudWatch does not perform unit conversions.
        """
        # TODO: Check if this part of the docs hold -> this seems to be impossible. When provided with a statistic,
        # it simply picks the first unit out of the list of allowed units, then returns the statistic based exclusively
        # on the values that have this particular unit. And there seems to be no way to not provide a statistic.

        # The list of allowed units seems to be:
        # [Megabits, Terabits, Gigabits, Count, Bytes, Gigabytes, Gigabytes / Second, Kilobytes, Kilobits / Second,
        # Terabytes, Terabits/Second, Bytes/Second, Percent, Megabytes, Megabits/Second, Milliseconds, Microseconds,
        # Kilobytes/Second, Gigabits/Second, Megabytes/Second, Bits, Bits/Second, Count/Second, Seconds, Kilobits,
        # Terabytes/Second, None ].

        namespace = f"n-sp-{short_uid()}"
        metric_name = "m-test"
        now = datetime.utcnow().replace(tzinfo=timezone.utc)

        for m in metric_data:
            m["MetricName"] = metric_name
            m["Timestamp"] = now
        aws_client.cloudwatch.put_metric_data(Namespace=namespace, MetricData=metric_data)

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=now,
                EndTime=now + timedelta(seconds=60),
                MaxDatapoints=10,
            )
            snapshot.match("get_metric_data_with_no_unit_specified", response)

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0.0
        retry(assert_results, retries=retries, sleep=1.0, sleep_before=sleep_before)

    @pytest.mark.parametrize(
        "input_pairs",
        [
            [("Sum", 60, "Seconds"), ("Minimum", 30, "Seconds")],
            [("Sum", 60, "Seconds"), ("Minimum", 60, "Seconds")],
            [("Sum", 60, "Seconds"), ("Sum", 30, "Seconds")],
            [("Sum", 60, "Seconds"), ("Minimum", 30, "Milliseconds")],
            [("Sum", 60, "Seconds"), ("Minimum", 60, "Milliseconds")],
            [("Sum", 60, "Seconds"), ("Sum", 30, "Milliseconds")],
            [("Sum", 60, "Seconds"), ("Sum", 60, "Milliseconds")],
        ],
    )
    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="not supported by the old provider")
    def test_label_generation(self, aws_client, snapshot, input_pairs):
        # Whenever values differ for a statistic type or period, that value is added to the label
        utc_now = datetime.now(tz=timezone.utc)

        namespace1 = f"test/{short_uid()}"
        # put metric data
        values = [0, 2, 7, 100]
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1,
            MetricData=[
                {"MetricName": "metric1", "Value": val, "Unit": "Seconds"} for val in values
            ],
        )

        # get_metric_data

        def _get_metric_data():
            return aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": f"result_{stat}_{str(period)}_{unit}",
                        "MetricStat": {
                            "Metric": {"Namespace": namespace1, "MetricName": "metric1"},
                            "Period": period,
                            "Stat": stat,
                            "Unit": unit,
                        },
                    }
                    for (stat, period, unit) in input_pairs
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

        def _match_results():
            response = _get_metric_data()
            # keep one assert to avoid storing incorrect values
            sum = [
                res for res in response["MetricDataResults"] if res["Id"].startswith("result_Sum")
            ][0]
            assert [int(val) for val in sum["Values"]] == [109]
            snapshot.match("label_generation", response)

        retry(_match_results, retries=10, sleep=1.0)

    @markers.aws.validated
    def test_get_metric_with_null_dimensions(self, aws_client, snapshot):
        """
        This test validates the behaviour when there is metric data with dimensions and the get_metric_data call
        has no dimensions specified. The expected behaviour is that the call should return the metric data with
        no dimensions, which in this test, there is no such data, so the total sum should equal 0. And since the
        Sum equals 0, the response will have no values.
        """
        snapshot.add_transformer(snapshot.transform.key_value("Id"))
        snapshot.add_transformer(snapshot.transform.key_value("Label"))
        namespace = f"n-{short_uid()}"
        metric_name = "m-test"
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 1,
                    "Unit": "Seconds",
                    "Dimensions": [
                        {
                            "Name": "foo",
                            "Value": "bar",
                        }
                    ],
                }
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "m1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": [],
                            },
                            "Period": 60,
                            "Stat": "Sum",
                        },
                    }
                ],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
            )
            assert len(response["MetricDataResults"][0]["Values"]) == 0
            snapshot.match("get_metric_with_null_dimensions", response)

        retry(assert_results, retries=10, sleep=1.0, sleep_before=2 if is_aws_cloud() else 0.0)

    @markers.aws.validated
    def test_alarm_lambda_target(
        self, aws_client, create_lambda_function, cleanups, account_id, snapshot
    ):
        snapshot.add_transformer(snapshot.transform.key_value("alarmName"))
        snapshot.add_transformer(
            snapshot.transform.key_value("namespace", reference_replacement=False)
        )
        fn_name = f"fn-cw-{short_uid()}"
        response = create_lambda_function(
            func_name=fn_name,
            handler_file=ACTION_LAMBDA,
            runtime="python3.11",
        )
        function_arn = response["CreateFunctionResponse"]["FunctionArn"]
        alarm_name = f"alarm-{short_uid()}"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            AlarmDescription="testing lambda alarm action",
            MetricName="metric1",
            Namespace=f"ns-{short_uid()}",
            Period=10,
            Threshold=2,
            Statistic="Average",
            OKActions=[],
            AlarmActions=[function_arn],
            EvaluationPeriods=2,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="ignore",
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        alarm_arn = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][
            0
        ]["AlarmArn"]
        # allow cloudwatch to trigger the lambda
        aws_client.lambda_.add_permission(
            FunctionName=fn_name,
            StatementId="AlarmAction",
            Action="lambda:InvokeFunction",
            Principal="lambda.alarms.cloudwatch.amazonaws.com",
            SourceAccount=account_id,
            SourceArn=alarm_arn,
        )
        aws_client.cloudwatch.set_alarm_state(
            AlarmName=alarm_name, StateValue="ALARM", StateReason="testing alarm"
        )

        # wait for lambda invocation
        def log_group_exists():
            return (
                len(
                    aws_client.logs.describe_log_groups(
                        logGroupNamePrefix=f"/aws/lambda/{fn_name}"
                    )["logGroups"]
                )
                == 1
            )

        wait_until(log_group_exists, max_retries=30 if is_aws_cloud() else 10)

        invocation_res = retry(
            lambda: _get_lambda_logs(aws_client.logs, fn_name=fn_name),
            retries=200 if is_aws_cloud() else 20,
            sleep=10 if is_aws_cloud() else 1,
        )
        snapshot.match("lambda-alarm-invocations", invocation_res)

    @markers.aws.validated
    def test_get_metric_with_no_results(self, snapshot, aws_client):
        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"n-{short_uid()}"
        metric = f"m-{short_uid()}"

        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Value": 1,
                }
            ],
        )

        def assert_metric_ready():
            list_of_metrics = aws_client.cloudwatch.list_metrics(
                Namespace=namespace, MetricName=metric
            )
            assert len(list_of_metrics["Metrics"]) == 1

        retry(assert_metric_ready, sleep=1, retries=10)

        data = aws_client.cloudwatch.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "result",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": namespace,
                            "MetricName": metric,
                            "Dimensions": [
                                {
                                    "Name": "foo",
                                    "Value": "bar",
                                }
                            ],
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=utc_now - timedelta(seconds=60),
            EndTime=utc_now + timedelta(seconds=60),
        )
        snapshot.add_transformer(snapshot.transform.key_value("Label"))
        snapshot.match("result", data)

    @markers.aws.only_localstack
    @pytest.mark.skipif(is_old_provider(), reason="old provider has known concurrency issues")
    # test some basic concurrency tasks
    def test_parallel_put_metric_data_list_metrics(self, aws_client):
        num_threads = 20
        create_barrier = threading.Barrier(num_threads)
        namespace = f"namespace-{short_uid()}"
        exception_caught = False

        def _put_metric_get_metric_data(runner: int):
            nonlocal create_barrier
            nonlocal namespace
            nonlocal exception_caught
            create_barrier.wait()
            try:
                if runner % 2:
                    aws_client.cloudwatch.put_metric_data(
                        Namespace=namespace,
                        MetricData=[
                            {
                                "MetricName": f"metric-{runner}-1",
                                "Value": 25,
                                "Unit": "Seconds",
                            },
                            {
                                "MetricName": f"metric-{runner}-2",
                                "Value": runner + 1,
                                "Unit": "Seconds",
                            },
                        ],
                    )
                else:
                    now = datetime.utcnow().replace(microsecond=0)
                    start_time = now - timedelta(minutes=10)
                    end_time = now + timedelta(minutes=5)
                    aws_client.cloudwatch.get_metric_data(
                        MetricDataQueries=[
                            {
                                "Id": "some",
                                "MetricStat": {
                                    "Metric": {
                                        "Namespace": namespace,
                                        "MetricName": f"metric-{runner - 1}-1",
                                    },
                                    "Period": 60,
                                    "Stat": "Sum",
                                },
                            },
                            {
                                "Id": "part",
                                "MetricStat": {
                                    "Metric": {
                                        "Namespace": namespace,
                                        "MetricName": f"metric-{runner - 1}-2",
                                    },
                                    "Period": 60,
                                    "Stat": "Sum",
                                },
                            },
                        ],
                        StartTime=start_time,
                        EndTime=end_time,
                    )
            except Exception as e:
                LOG.exception("runner %s failed: %s", runner, e)
                exception_caught = True

        thread_list = []
        for i in range(1, num_threads + 1):
            thread = threading.Thread(target=_put_metric_get_metric_data, args=[i])
            thread.start()
            thread_list.append(thread)

        for thread in thread_list:
            thread.join()

        assert not exception_caught
        metrics = aws_client.cloudwatch.list_metrics(Namespace=namespace)["Metrics"]
        assert 20 == len(metrics)  # every second thread inserted two metrics

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..describe-alarm.MetricAlarms..AlarmDescription",
            "$..describe-alarm.MetricAlarms..StateTransitionedTimestamp",
        ],
    )
    def test_delete_alarm(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())

        alarm_name = "test-alarm"
        aws_client.cloudwatch.put_metric_alarm(
            AlarmName="test-alarm",
            Namespace=f"my-namespace-{short_uid()}",
            MetricName="metric1",
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
            Period=60,
            Statistic="Sum",
            Threshold=30,
        )
        result = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe-alarm", result)

        delete_result = aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name])
        snapshot.match("delete-alarm", delete_result)

        describe_alarm = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe-after-delete", describe_alarm)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        condition=is_old_provider,
        paths=[
            "$..list-metrics..Metrics",
        ],
    )
    def test_multiple_dimensions_statistics(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())

        utc_now = datetime.now(tz=timezone.utc)
        namespace = f"test/{short_uid()}"
        metric_name = "http.server.requests.count"
        dimensions = [
            {"Name": "error", "Value": "none"},
            {"Name": "exception", "Value": "none"},
            {"Name": "method", "Value": "GET"},
            {"Name": "outcome", "Value": "SUCCESS"},
            {"Name": "uri", "Value": "/greetings"},
            {"Name": "status", "Value": "200"},
        ]
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 0.0,
                    "Unit": "Count",
                    "StorageResolution": 1,
                    "Dimensions": dimensions,
                    "Timestamp": datetime.now(tz=timezone.utc),
                }
            ],
        )
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric_name,
                    "Value": 5.0,
                    "Unit": "Count",
                    "StorageResolution": 1,
                    "Dimensions": dimensions,
                    "Timestamp": datetime.now(tz=timezone.utc),
                }
            ],
        )

        def assert_results():
            response = aws_client.cloudwatch.get_metric_data(
                MetricDataQueries=[
                    {
                        "Id": "result1",
                        "MetricStat": {
                            "Metric": {
                                "Namespace": namespace,
                                "MetricName": metric_name,
                                "Dimensions": dimensions,
                            },
                            "Period": 10,
                            "Stat": "Maximum",
                            "Unit": "Count",
                        },
                    }
                ],
                StartTime=utc_now - timedelta(seconds=60),
                EndTime=utc_now + timedelta(seconds=60),
            )

            assert len(response["MetricDataResults"][0]["Values"]) > 0
            snapshot.match("get-metric-stats-max", response)

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0
        retry(assert_results, retries=retries, sleep_before=sleep_before)

        def list_metrics():
            res = aws_client.cloudwatch.list_metrics(
                Namespace=namespace, MetricName=metric_name, Dimensions=dimensions
            )
            assert len(res["Metrics"]) > 0
            return res

        retries = 10 if is_aws_cloud() else 1
        sleep_before = 2 if is_aws_cloud() else 0
        list_metrics_res = retry(list_metrics, retries=retries, sleep_before=sleep_before)

        # Function to sort the dimensions by "Name"
        def sort_dimensions(data: dict):
            for metric in data["Metrics"]:
                metric["Dimensions"] = sorted(metric["Dimensions"], key=lambda x: x["Name"])

        sort_dimensions(list_metrics_res)
        snapshot.match("list-metrics", list_metrics_res)

    @markers.aws.validated
    @pytest.mark.skipif(is_old_provider(), reason="New test for v2 provider")
    def test_invalid_amount_of_datapoints(self, aws_client, snapshot):
        snapshot.add_transformer(snapshot.transform.cloudwatch_api())
        utc_now = datetime.now(tz=timezone.utc)
        with pytest.raises(ClientError) as ex:
            aws_client.cloudwatch.get_metric_statistics(
                Namespace="namespace",
                MetricName="metric_name",
                StartTime=utc_now,
                EndTime=utc_now + timedelta(days=1),
                Period=1,
                Statistics=["SampleCount"],
            )

        snapshot.match("error-invalid-amount-datapoints", ex.value.response)
        with pytest.raises(ClientError) as ex:
            aws_client.cloudwatch.get_metric_statistics(
                Namespace="namespace",
                MetricName="metric_name",
                StartTime=utc_now,
                EndTime=utc_now,
                Period=1,
                Statistics=["SampleCount"],
            )

        snapshot.match("error-invalid-time-frame", ex.value.response)

        response = aws_client.cloudwatch.get_metric_statistics(
            Namespace=f"namespace_{short_uid()}",
            MetricName="metric_name",
            StartTime=utc_now,
            EndTime=utc_now + timedelta(days=1),
            Period=60,
            Statistics=["SampleCount"],
        )

        snapshot.match("get-metric-statitics", response)


def _get_lambda_logs(logs_client: "CloudWatchLogsClient", fn_name: str):
    log_events = logs_client.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")["events"]
    filtered_logs = [event for event in log_events if event["message"].startswith("{")]
    assert len(filtered_logs) >= 1
    filtered_logs.sort(key=lambda e: e["timestamp"], reverse=True)
    return filtered_logs[0]["message"]


def _check_alarm_triggered(
    expected_state,
    alarm_name,
    cloudwatch_client,
    snapshot=None,
    identifier=None,
):
    response = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
    assert response["MetricAlarms"][0]["StateValue"] == expected_state
    if snapshot:
        snapshot.match(f"{identifier}-describe", response)


def _sqs_messages_snapshot(expected_state, sqs_client, sqs_queue, snapshot, identifier):
    result = sqs_client.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=2, VisibilityTimeout=0)
    found_msg = None
    receipt_handle = None
    for msg in result["Messages"]:
        body = json.loads(msg["Body"])
        message = json.loads(body["Message"])
        if message["NewStateValue"] == expected_state:
            found_msg = message
            receipt_handle = msg["ReceiptHandle"]
            break
    assert found_msg, f"no message found for {expected_state}. Got {len(result['Messages'])} messages.\n{json.dumps(result)}"
    sqs_client.delete_message(QueueUrl=sqs_queue, ReceiptHandle=receipt_handle)
    snapshot.match(f"{identifier}-sqs-msg", found_msg)


def check_message(
    sqs_client,
    expected_queue_url,
    expected_topic_arn,
    expected_new,
    expected_reason,
    alarm_name,
    alarm_description,
    expected_trigger,
):
    receive_result = sqs_client.receive_message(QueueUrl=expected_queue_url)
    message = None
    for msg in receive_result["Messages"]:
        body = json.loads(msg["Body"])
        if body["TopicArn"] == expected_topic_arn:
            message = json.loads(body["Message"])
            receipt_handle = msg["ReceiptHandle"]
            sqs_client.delete_message(QueueUrl=expected_queue_url, ReceiptHandle=receipt_handle)
            break
    assert message["NewStateValue"] == expected_new
    assert message["NewStateReason"] == expected_reason
    assert message["AlarmName"] == alarm_name
    assert message["AlarmDescription"] == alarm_description
    assert message["Trigger"] == expected_trigger
    return message


def get_sqs_policy(sqs_queue_arn, sns_topic_arn):
    return f"""
{{
  "Version":"2012-10-17",
  "Statement":[
    {{
      "Effect": "Allow",
      "Principal": {{ "AWS": "*" }},
      "Action": "sqs:SendMessage",
      "Resource": "{sqs_queue_arn}",
      "Condition":{{
        "ArnEquals":{{
        "aws:SourceArn":"{sns_topic_arn}"
        }}
      }}
    }}
  ]
}}
"""


ACTION_LAMBDA = """
def handler(event, context):
    import json
    print(json.dumps(event))
    return {"triggered": True}
"""
