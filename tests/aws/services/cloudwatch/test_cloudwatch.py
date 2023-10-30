import copy
import gzip
import json
from datetime import datetime, timedelta, timezone
from urllib.request import Request, urlopen

import pytest
import requests

from localstack import config
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_REGION_NAME
from localstack.services.cloudwatch.provider import PATH_GET_RAW_METRICS
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import retry, short_uid, to_str
from localstack.utils.sync import poll_condition

PUBLICATION_RETRIES = 5


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
    def test_put_metric_data_gzip(self, aws_client):
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
        headers = aws_stack.mock_aws_request_headers(
            "cloudwatch",
            internal=True,
            region_name=TEST_AWS_REGION_NAME,
            access_key=TEST_AWS_ACCESS_KEY_ID,
        )
        authorization = aws_stack.mock_aws_request_headers(
            "monitoring",
            region_name=TEST_AWS_REGION_NAME,
            access_key=TEST_AWS_ACCESS_KEY_ID,
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
        request = Request(url, encoded_data, headers, method="POST")
        urlopen(request)

        rs = aws_client.cloudwatch.list_metrics(Namespace=namespace, MetricName=metric_name)
        assert 1 == len(rs["Metrics"])
        assert namespace == rs["Metrics"][0]["Namespace"]

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

    @markers.aws.only_localstack
    def test_raw_metric_data(self, aws_client):
        """
        tests internal endpoint at "/_aws/cloudwatch/metrics/raw"
        """
        namespace1 = f"test/{short_uid()}"
        aws_client.cloudwatch.put_metric_data(
            Namespace=namespace1, MetricData=[dict(MetricName="someMetric", Value=23)]
        )
        url = f"{config.get_edge_url()}{PATH_GET_RAW_METRICS}"
        headers = aws_stack.mock_aws_request_headers(
            "cloudwatch",
            region_name=TEST_AWS_REGION_NAME,
            access_key=TEST_AWS_ACCESS_KEY_ID,
        )
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
        alarm_name = f"a-{short_uid()}"
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
    def test_put_composite_alarm_describe_alarms_converts_date_format_correctly(
        self, aws_client, cleanups
    ):
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
        paths=["$..MetricAlarms..AlarmDescription", "$..MetricAlarms..StateTransitionedTimestamp"]
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
                    "MetricName": "Memory",
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
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": "i-46cdcd06a11207ab3"}],
                    "Value": 15,
                }
            ],
        )

        def _count_metrics():
            results = aws_client.cloudwatch.list_metrics(Namespace=namespace)["Metrics"]
            assert len(results) == 2

        # asserting only unique values are returned
        retry(_count_metrics, retries=retries, sleep_before=sleep_seconds)

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
    def test_set_alarm(self, sns_create_topic, sqs_create_queue, aws_client, cleanups):
        # create topics for state 'ALARM' and 'OK'
        sns_topic_alarm = sns_create_topic()
        topic_arn_alarm = sns_topic_alarm["TopicArn"]
        sns_topic_ok = sns_create_topic()
        topic_arn_ok = sns_topic_ok["TopicArn"]

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

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..evaluatedDatapoints",
            "$..startDate",  # only sometimes visible? part of StateReasonData
            "$..alarm-triggered-describe.MetricAlarms[0].StateReason",  # reason contains datapoint + date
            "$..alarm-triggered-sqs-msg.NewStateReason",
        ]
    )
    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="SQS messages do not work reliably, test is flaky"
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
        aws_client.cloudwatch.put_metric_data(Namespace=namespace, MetricData=data)

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
            TreatMissingData="notBreaching",
        )
        cleanups.append(lambda: aws_client.cloudwatch.delete_alarms(AlarmNames=[alarm_name]))
        response = aws_client.cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        snapshot.match("describe-alarm", response)
        retry(
            _check_alarm_triggered,
            retries=60,
            sleep=3.0,
            sleep_before=5,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            alarm_name=alarm_name,
            cloudwatch_client=aws_client.cloudwatch,
            snapshot=snapshot,
            identifier="alarm-triggered",
        )

        # missing are treated as not breaching, so we should reach OK state again
        retry(
            _check_alarm_triggered,
            retries=60,
            sleep=3.0,
            sleep_before=5,
            expected_state="OK",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            alarm_name=alarm_name,
            cloudwatch_client=aws_client.cloudwatch,
            snapshot=snapshot,
            identifier="ok-triggered",
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..evaluatedDatapoints", "$..StateTransitionedTimestamp"]
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
            _check_alarm_triggered,
            retries=80,
            sleep=3.0,
            sleep_before=5,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            alarm_name=alarm_name,
            cloudwatch_client=aws_client.cloudwatch,
            snapshot=snapshot,
            identifier="alarm-1",
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..MetricAlarms..StateTransitionedTimestamp"])
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
            _check_alarm_triggered,
            retries=80,
            sleep=3.0,
            sleep_before=5,
            expected_state="ALARM",
            sqs_client=aws_client.sqs,
            sqs_queue=sqs_queue,
            alarm_name=alarm_name,
            cloudwatch_client=aws_client.cloudwatch,
            snapshot=snapshot,
            identifier="alarm-state",
        )

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


def _check_alarm_triggered(
    expected_state,
    alarm_name,
    cloudwatch_client,
    sqs_client=None,
    sqs_queue=None,
    snapshot=None,
    identifier=None,
):
    response = cloudwatch_client.describe_alarms(AlarmNames=[alarm_name])
    assert response["MetricAlarms"][0]["StateValue"] == expected_state
    if snapshot:
        snapshot.match(f"{identifier}-describe", response)
    if not sqs_queue or not sqs_client:
        return

    result = sqs_client.receive_message(QueueUrl=sqs_queue, VisibilityTimeout=0)

    msg = result["Messages"][0]

    body = json.loads(msg["Body"])
    message = json.loads(body["Message"])
    if snapshot:
        snapshot.match(f"{identifier}-sqs-msg", message)
    receipt_handle = msg["ReceiptHandle"]
    sqs_client.delete_message(QueueUrl=sqs_queue, ReceiptHandle=receipt_handle)
    assert message["NewStateValue"] == expected_state


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
