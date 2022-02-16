import gzip
import json
from datetime import datetime, timedelta
from urllib.request import Request, urlopen

import requests
from dateutil.tz import tzutc

from localstack import config
from localstack.services.cloudwatch.provider import PATH_GET_RAW_METRICS
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid, to_str

PUBLICATION_RETRIES = 5


class TestCloudwatch:
    def test_put_metric_data(self, cloudwatch_client):
        metric_name = "metric-%s" % short_uid()
        namespace = "namespace-%s" % short_uid()

        # Put metric data without value
        data = [
            {
                "MetricName": metric_name,
                "Dimensions": [{"Name": "foo", "Value": "bar"}],
                "Timestamp": datetime(2019, 1, 3, tzinfo=tzutc()),
                "Unit": "Seconds",
            }
        ]
        rs = cloudwatch_client.put_metric_data(Namespace=namespace, MetricData=data)
        assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        # Get metric statistics
        rs = cloudwatch_client.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=datetime(2019, 1, 1),
            EndTime=datetime(2019, 1, 10),
            Period=120,
            Statistics=["Average"],
        )
        assert metric_name == rs["Label"]
        assert 1 == len(rs["Datapoints"])
        assert data[0]["Timestamp"] == rs["Datapoints"][0]["Timestamp"]

        rs = cloudwatch_client.list_metrics(Namespace=namespace, MetricName=metric_name)
        assert 1 == len(rs["Metrics"])
        assert namespace == rs["Metrics"][0]["Namespace"]

    def test_put_metric_data_gzip(self, cloudwatch_client):
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

        rs = cloudwatch_client.list_metrics(Namespace=namespace, MetricName=metric_name)
        assert 1 == len(rs["Metrics"])
        assert namespace == rs["Metrics"][0]["Namespace"]

    def test_get_metric_data(self, cloudwatch_client):

        cloudwatch_client.put_metric_data(
            Namespace="some/thing", MetricData=[dict(MetricName="someMetric", Value=23)]
        )
        cloudwatch_client.put_metric_data(
            Namespace="some/thing", MetricData=[dict(MetricName="someMetric", Value=18)]
        )
        cloudwatch_client.put_metric_data(
            Namespace="ug/thing", MetricData=[dict(MetricName="ug", Value=23)]
        )

        # filtering metric data with current time interval
        response = cloudwatch_client.get_metric_data(
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

        assert 2 == len(response["MetricDataResults"])

        for data_metric in response["MetricDataResults"]:
            if data_metric["Id"] == "some":
                assert 41.0 == data_metric["Values"][0]
            if data_metric["Id"] == "part":
                assert 23.0 == data_metric["Values"][0]

        # filtering metric data with current time interval
        response = cloudwatch_client.get_metric_data(
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
                assert len(data_metric["Values"]) == 0
            if data_metric["Id"] == "part":
                assert len(data_metric["Values"]) == 0

        # get raw metric data
        url = "%s%s" % (config.get_edge_url(), PATH_GET_RAW_METRICS)
        result = requests.get(url)
        assert 200 == result.status_code
        result = json.loads(to_str(result.content))
        assert len(result["metrics"]) >= 3

    def test_multiple_dimensions(self, cloudwatch_client):

        namespaces = [
            "ns1-%s" % short_uid(),
            "ns2-%s" % short_uid(),
            "ns3-%s" % short_uid(),
        ]
        num_dimensions = 2
        for ns in namespaces:
            for i in range(3):
                rs = cloudwatch_client.put_metric_data(
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
                assert 200 == rs["ResponseMetadata"]["HTTPStatusCode"]

        rs = cloudwatch_client.list_metrics()
        metrics = [m for m in rs["Metrics"] if m.get("Namespace") in namespaces]
        assert metrics
        assert len(metrics) == len(namespaces) * num_dimensions

    def test_describe_alarms_converts_date_format_correctly(self, cloudwatch_client):
        alarm_name = "a-%s" % short_uid()
        cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
        )
        try:
            result = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
            alarm = result["MetricAlarms"][0]
            assert isinstance(alarm["AlarmConfigurationUpdatedTimestamp"], datetime)
            assert isinstance(alarm["StateUpdatedTimestamp"], datetime)
        finally:
            cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])

    def test_put_composite_alarm_describe_alarms_converts_date_format_correctly(
        self, cloudwatch_client
    ):
        alarm_name = "a-%s" % short_uid()
        alarm_rule = 'ALARM("my_other_alarm")'
        cloudwatch_client.put_composite_alarm(
            AlarmName=alarm_name,
            AlarmRule=alarm_rule,
        )
        try:
            result = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
            alarm = result["CompositeAlarms"][0]
            assert alarm["AlarmName"] == alarm_name
            assert alarm["AlarmRule"] == alarm_rule
        finally:
            cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])

    def test_store_tags(self, cloudwatch_client):
        alarm_name = "a-%s" % short_uid()
        response = cloudwatch_client.put_metric_alarm(
            AlarmName=alarm_name,
            EvaluationPeriods=1,
            ComparisonOperator="GreaterThanThreshold",
        )
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        alarm_arn = aws_stack.cloudwatch_alarm_arn(alarm_name)

        tags = [{"Key": "tag1", "Value": "foo"}, {"Key": "tag2", "Value": "bar"}]
        response = cloudwatch_client.tag_resource(ResourceARN=alarm_arn, Tags=tags)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        response = cloudwatch_client.list_tags_for_resource(ResourceARN=alarm_arn)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        assert tags, response["Tags"]
        response = cloudwatch_client.untag_resource(ResourceARN=alarm_arn, TagKeys=["tag1"])
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        response = cloudwatch_client.list_tags_for_resource(ResourceARN=alarm_arn)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]
        assert [{"Key": "tag2", "Value": "bar"}] == response["Tags"]

        # clean up
        cloudwatch_client.delete_alarms(AlarmNames=[alarm_name])

    def test_list_metrics_uniqueness(self, cloudwatch_client):
        # create metrics with same namespace and dimensions but different metric names
        cloudwatch_client.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )
        cloudwatch_client.put_metric_data(
            Namespace="AWS/EC2",
            MetricData=[
                {
                    "MetricName": "Memory",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 30,
                }
            ],
        )
        results = cloudwatch_client.list_metrics(Namespace="AWS/EC2")["Metrics"]
        assert 2 == len(results)
        # duplicating existing metric
        cloudwatch_client.put_metric_data(
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
        results = cloudwatch_client.list_metrics(Namespace="AWS/EC2")["Metrics"]
        assert 2 == len(results)

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
