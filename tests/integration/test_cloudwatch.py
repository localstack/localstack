import gzip
import json
import unittest
from datetime import datetime, timedelta

import requests
from dateutil.tz import tzutc
from six.moves.urllib.request import Request, urlopen

from localstack import config
from localstack.services.cloudwatch.cloudwatch_listener import PATH_GET_RAW_METRICS
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_str


class CloudWatchTest(unittest.TestCase):
    def test_put_metric_data(self):
        metric_name = "metric-%s" % short_uid()
        namespace = "namespace-%s" % short_uid()

        client = aws_stack.create_external_boto_client("cloudwatch")

        # Put metric data without value
        data = [
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "foo", "Value": "bar"}],
                "Timestamp": datetime(2019, 1, 3, tzinfo=tzutc()),
                "Unit": "Seconds",
            }
        ]
        rs = client.put_metric_data(Namespace=namespace, MetricData=data)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        # Get metric statistics
        rs = client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=datetime(2019, 1, 1),
            EndTime=datetime(2019, 1, 10),
            Period=120,
            Statistics=["Average"],
        )
        self.assertEqual(metric_name, rs["Label"])
        self.assertEqual(1, len(rs["Datapoints"]))
        self.assertEqual(data[0]["Timestamp"], rs["Datapoints"][0]["Timestamp"])

        rs = client.list_metrics(Namespace=namespace, MetricName=metric_name)
        self.assertEqual(1, len(rs["Metrics"]))
        self.assertEqual(namespace, rs["Metrics"][0]["Namespace"])

    def test_put_metric_data_gzip(self):
        metric_name = "test-metric"
        namespace = "namespace"
        data = (
            "Action=PutMetricData&MetricData.member.1."
            "MetricName=%s&MetricData.member.1.Value=1&"
            "Namespace=%s&Version=2010-08-01" % (metric_name, namespace)
        )
        bytes_data = bytes(data, encoding="utf-8")
        encoded_data = gzip.compress(bytes_data)

        url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers("cloudwatch")
        authorization = aws_stack.mock_aws_request_headers("monitoring")["Authorization"]

        headers.update(
            {
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "Content-Length": len(encoded_data),
                "Content-Encoding": "GZIP",
                "User-Agent": "aws-sdk-nodejs/2.819.0 linux/v12.18.2 callback",
                "Authorization": authorization,
            }
        )
        request = Request(url, encoded_data, headers, method="POST")
        urlopen(request)

        client = aws_stack.create_external_boto_client("cloudwatch")
        rs = client.list_metrics(Namespace=namespace, MetricName=metric_name)
        self.assertEqual(1, len(rs["Metrics"]))
        self.assertEqual(namespace, rs["Metrics"][0]["Namespace"])

    def test_get_metric_data(self):

        conn = aws_stack.create_external_boto_client("cloudwatch")

        conn.put_metric_data(
            Namespace="some/thing", MetricData=[dict(MetricName="someMetric", Value=23)]
        )
        conn.put_metric_data(
            Namespace="some/thing", MetricData=[dict(MetricName="someMetric", Value=18)]
        )
        conn.put_metric_data(Namespace="ug/thing", MetricData=[dict(MetricName="ug", Value=23)])

        # filtering metric data with current time interval
        response = conn.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "some",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "some/thing",
                            "MetricName": "someMetric",
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                },
                {
                    "Id": "part",
                    "MetricStat": {
                        "Metric": {"Namespace": "ug/thing", "MetricName": "ug"},
                        "Period": 60,
                        "Stat": "Sum",
                    },
                },
            ],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )

        self.assertEqual(2, len(response["MetricDataResults"]))

        for data_metric in response["MetricDataResults"]:
            if data_metric["Id"] == "some":
                self.assertEqual(41.0, data_metric["Values"][0])
            if data_metric["Id"] == "part":
                self.assertEqual(23.0, data_metric["Values"][0])

        # filtering metric data with current time interval
        response = conn.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "some",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "some/thing",
                            "MetricName": "someMetric",
                        },
                        "Period": 60,
                        "Stat": "Sum",
                    },
                },
                {
                    "Id": "part",
                    "MetricStat": {
                        "Metric": {"Namespace": "ug/thing", "MetricName": "ug"},
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
                self.assertEqual(0, len(data_metric["Values"]))
            if data_metric["Id"] == "part":
                self.assertEqual(0, len(data_metric["Values"]))

        # get raw metric data
        url = "%s%s" % (config.get_edge_url(), PATH_GET_RAW_METRICS)
        result = requests.get(url)
        self.assertEqual(200, result.status_code)
        result = json.loads(to_str(result.content))
        self.assertGreaterEqual(len(result["metrics"]), 3)

    def test_multiple_dimensions(self):
        client = aws_stack.create_external_boto_client("cloudwatch")

        namespaces = [
            "ns1-%s" % short_uid(),
            "ns2-%s" % short_uid(),
            "ns3-%s" % short_uid(),
        ]
        num_dimensions = 2
        for ns in namespaces:
            for i in range(3):
                rs = client.put_metric_data(
                    Namespace=ns,
                    MetricData=[
                        {
                            "MetricName": "someMetric",
                            "Value": 123,
                            "Dimensions": [
                                {
                                    "Name": "foo",
                                    "Value": "bar-%s" % (i % num_dimensions),
                                }
                            ],
                        }
                    ],
                )
                self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rs = client.list_metrics()
        metrics = [m for m in rs["Metrics"] if m.get("Namespace") in namespaces]
        self.assertTrue(metrics)
        self.assertEqual(len(metrics), len(namespaces) * num_dimensions)

    def test_store_tags(self):
        cloudwatch = aws_stack.create_external_boto_client("cloudwatch")

        alarm_name = "a-%s" % short_uid()
        response = cloudwatch.put_metric_alarm(
            AlarmName=alarm_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        alarm_arn = aws_stack.cloudwatch_alarm_arn(alarm_name)

        tags = [{"Key": "tag1", "Value": "foo"}, {"Key": "tag2", "Value": "bar"}]
        response = cloudwatch.tag_resource(ResourceARN=alarm_arn, Tags=tags)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        response = cloudwatch.list_tags_for_resource(ResourceARN=alarm_arn)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(tags, response["Tags"])
        response = cloudwatch.untag_resource(ResourceARN=alarm_arn, TagKeys=["tag1"])
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        response = cloudwatch.list_tags_for_resource(ResourceARN=alarm_arn)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual([{"Key": "tag2", "Value": "bar"}], response["Tags"])

        # clean up
        cloudwatch.delete_alarms(AlarmNames=[alarm_name])
