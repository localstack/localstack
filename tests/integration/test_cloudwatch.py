import gzip
import json
import unittest
from datetime import datetime, timedelta
from urllib.request import Request, urlopen

import requests
from dateutil.tz import tzutc

from localstack import config
from localstack.services.cloudwatch.cloudwatch_listener import PATH_GET_RAW_METRICS
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid, to_str

PUBLICATION_RETRIES = 5


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

    def test_list_metrics_uniqueness(self):
        cloudwatch = aws_stack.create_external_boto_client("cloudwatch")
        # create metrics with same namespace and dimensions but different metric names
        cloudwatch.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )
        cloudwatch.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "Memory",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 30,
                }
            ],
        )
        results = cloudwatch.list_metrics(Namespace="AWS/EC2")["Metrics"]
        self.assertEqual(2, len(results))
        # duplicating existing metric
        cloudwatch.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )
        # asserting only unique values are returned
        results = cloudwatch.list_metrics(Namespace="AWS/EC2")["Metrics"]
        self.assertEqual(2, len(results))


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


class TestCloudwatch:
    def test_set_alarm(
        self, sns_client, cloudwatch_client, sqs_client, sns_create_topic, sqs_create_queue
    ):
        # create topics for state 'ALARM' and 'OK'
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        sns_topic_ok = sns_create_topic()
        topic_arn_ok = sns_topic_ok["TopicArn"]

        # create queues for 'ALARM' and 'OK' (will receive sns messages)
        uid = short_uid()
        queue_url_alarm = sqs_create_queue(QueueName=f"AlarmQueue-{uid}")
        queue_url_ok = sqs_create_queue(QueueName=f"OKQueue-{uid}")

        arn_queue_alarm = sqs_client.get_queue_attributes(
            QueueUrl=queue_url_alarm, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        arn_queue_ok = sqs_client.get_queue_attributes(
            QueueUrl=queue_url_ok, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url_alarm,
            Attributes={"Policy": get_sqs_policy(arn_queue_alarm, topic_arn_alarm)},
        )
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url_ok, Attributes={"Policy": get_sqs_policy(arn_queue_ok, topic_arn_ok)}
        )

        alarm_name = "test-alarm"
        alarm_description = "Test Alarm when CPU exceeds 50 percent"

        expected_trigger = {
            "MetricName": "CPUUtilization",
            "Namespace": "AWS/EC2",
            "Unit": "Percent",
            "Period": 300,
            "EvaluationPeriods": 1,
            "ComparisonOperator": "GreaterThanThreshold",
            "Threshold": 50.0,
            "TreatMissingData": "ignore",
            "EvaluateLowSampleCountPercentile": "",
            "Dimensions": [{"value": "i-0317828c84edbe100", "name": "InstanceId"}],
            "StatisticType": "Statistic",
            "Statistic": "AVERAGE",
        }
        try:
            # subscribe to SQS
            subscription_alarm = sns_client.subscribe(
                TopicArn=topic_arn_alarm, Protocol="sqs", Endpoint=arn_queue_alarm
            )
            subscription_ok = sns_client.subscribe(
                TopicArn=topic_arn_ok, Protocol="sqs", Endpoint=arn_queue_ok
            )

            # create alarm with actions for "OK" and "ALARM"
            cloudwatch_client.put_metric_alarm(
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

            # trigger alarm
            state_value = "ALARM"
            state_reason = "testing alarm"
            cloudwatch_client.set_alarm_state(
                AlarmName=alarm_name, StateReason=state_reason, StateValue=state_value
            )

            retry(
                check_message,
                retries=PUBLICATION_RETRIES,
                sleep_before=1,
                sqs_client=sqs_client,
                expected_queue_url=queue_url_alarm,
                expected_topic_arn=topic_arn_alarm,
                expected_new=state_value,
                expected_reason=state_reason,
                alarm_name=alarm_name,
                alarm_description=alarm_description,
                expected_trigger=expected_trigger,
            )

            # trigger OK
            state_value = "OK"
            state_reason = "resetting alarm"
            cloudwatch_client.set_alarm_state(
                AlarmName=alarm_name, StateReason=state_reason, StateValue=state_value
            )

            retry(
                check_message,
                retries=PUBLICATION_RETRIES,
                sleep_before=1,
                sqs_client=sqs_client,
                expected_queue_url=queue_url_ok,
                expected_topic_arn=topic_arn_ok,
                expected_new=state_value,
                expected_reason=state_reason,
                alarm_name=alarm_name,
                alarm_description=alarm_description,
                expected_trigger=expected_trigger,
            )
        finally:
            # cleanup
            sns_client.unsubscribe(SubscriptionArn=subscription_alarm["SubscriptionArn"])
            sns_client.unsubscribe(SubscriptionArn=subscription_ok["SubscriptionArn"])
            cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])
