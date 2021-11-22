# -*- coding: utf-8 -*-
import unittest
from datetime import datetime, timedelta

from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.services.awslambda.lambda_api import func_arn
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import now_utc, retry, short_uid
from tests.integration.test_lambda import (
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NAME_PY3,
    TEST_LAMBDA_PYTHON3,
)


class CloudWatchLogsTest(unittest.TestCase):
    def setUp(self):
        self.logs_client = aws_stack.connect_to_service("logs")

    def test_put_events_multi_bytes_msg(self):
        group = "g-%s" % short_uid()
        stream = "s-%s" % short_uid()

        groups_before = testutil.list_all_resources(
            lambda kwargs: self.logs_client.describe_log_groups(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="logGroups",
        )

        self.create_log_group_and_stream(group, stream)

        groups_after = testutil.list_all_resources(
            lambda kwargs: self.logs_client.describe_log_groups(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="logGroups",
        )

        self.assertEqual(len(groups_before) + 1, len(groups_after))

        # send message with non-ASCII (multi-byte) chars
        body_msg = "🙀 - 参よ - 日本語"
        events = [{"timestamp": now_utc(millis=True), "message": body_msg}]
        response = self.logs_client.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=events
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        events = self.logs_client.get_log_events(logGroupName=group, logStreamName=stream)["events"]
        self.assertEqual(body_msg, events[0]["message"])

        # clean up
        self.logs_client.delete_log_group(logGroupName=group)

    def test_filter_log_events_response_header(self):
        group = "lg-%s" % short_uid()
        stream = "ls-%s" % short_uid()

        self.create_log_group_and_stream(group, stream)

        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        self.logs_client.put_log_events(logGroupName=group, logStreamName=stream, logEvents=events)

        rs = self.logs_client.filter_log_events(logGroupName=group)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(
            APPLICATION_AMZ_JSON_1_1,
            rs["ResponseMetadata"]["HTTPHeaders"]["content-type"],
        )

        # clean up
        self.logs_client.delete_log_group(logGroupName=group)

    def test_list_tags_log_group(self):
        group = "lg-%s" % short_uid()
        self.logs_client.create_log_group(logGroupName=group, tags={"env": "testing1"})
        rs = self.logs_client.list_tags_log_group(logGroupName=group)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertIn("tags", rs)
        self.assertEqual("testing1", rs["tags"]["env"])

        # clean up
        self.logs_client.delete_log_group(logGroupName=group)

    def test_put_subscription_filter_lambda(self):
        lambda_client = aws_stack.connect_to_service("lambda")

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON3,
            libs=TEST_LAMBDA_LIBS,
            func_name=TEST_LAMBDA_NAME_PY3,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        lambda_client.invoke(FunctionName=TEST_LAMBDA_NAME_PY3, Payload=b"{}")

        log_group_name = "/aws/lambda/{}".format(TEST_LAMBDA_NAME_PY3)

        self.logs_client.put_subscription_filter(
            logGroupName=log_group_name,
            filterName="test",
            filterPattern="",
            destinationArn=func_arn(TEST_LAMBDA_NAME_PY3),
        )
        stream = "ls-%s" % short_uid()
        self.logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=stream)

        self.logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=stream,
            logEvents=[
                {"timestamp": now_utc(millis=True), "message": "test"},
                {"timestamp": now_utc(millis=True), "message": "test 2"},
            ],
        )

        resp2 = self.logs_client.describe_subscription_filters(logGroupName=log_group_name)
        self.assertEqual(1, len(resp2["subscriptionFilters"]))

        def check_invocation():
            events = testutil.get_lambda_log_events(TEST_LAMBDA_NAME_PY3)
            self.assertEqual(2, len(events))

        retry(check_invocation, retries=6, sleep=3.0)

    def test_put_subscription_filter_firehose(self):
        log_group = "lg-%s" % short_uid()
        log_stream = "ls-%s" % short_uid()
        s3_bucket = "s3-%s" % short_uid()
        s3_bucket_arn = "arn:aws:s3:::{}".format(s3_bucket)
        firehose = "firehose-%s" % short_uid()

        s3_client = aws_stack.connect_to_service("s3")
        firehose_client = aws_stack.connect_to_service("firehose")

        s3_client.create_bucket(Bucket=s3_bucket)
        response = firehose_client.create_delivery_stream(
            DeliveryStreamName=firehose,
            S3DestinationConfiguration={
                "BucketARN": s3_bucket_arn,
                "RoleARN": "arn:aws:iam::000000000000:role/FirehosetoS3Role",
            },
        )
        firehose_arn = response["DeliveryStreamARN"]

        self.create_log_group_and_stream(log_group, log_stream)

        self.logs_client.put_subscription_filter(
            logGroupName=log_group,
            filterName="Destination",
            filterPattern="",
            destinationArn=firehose_arn,
        )

        self.logs_client.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[
                {"timestamp": now_utc(millis=True), "message": "test"},
                {"timestamp": now_utc(millis=True), "message": "test 2"},
            ],
        )

        self.logs_client.put_log_events(
            logGroupName=log_group,
            logStreamName=log_stream,
            logEvents=[
                {"timestamp": now_utc(millis=True), "message": "test"},
                {"timestamp": now_utc(millis=True), "message": "test 2"},
            ],
        )

        response = s3_client.list_objects(Bucket=s3_bucket)
        self.assertEqual(2, len(response["Contents"]))

        # clean up
        self.cleanup(log_group, log_stream)
        firehose_client.delete_delivery_stream(DeliveryStreamName=firehose, AllowForceDelete=True)

    def test_put_subscription_filter_kinesis(self):
        log_group = "lg-%s" % short_uid()
        log_stream = "ls-%s" % short_uid()
        kinesis = "kinesis-%s" % short_uid()

        kinesis_client = aws_stack.connect_to_service("kinesis")

        self.create_log_group_and_stream(log_group, log_stream)

        kinesis_client.create_stream(StreamName=kinesis, ShardCount=1)

        kinesis_arn = kinesis_client.describe_stream(StreamName=kinesis)["StreamDescription"][
            "StreamARN"
        ]

        self.logs_client.put_subscription_filter(
            logGroupName=log_group,
            filterName="Destination",
            filterPattern="",
            destinationArn=kinesis_arn,
        )

        def put_event():
            self.logs_client.put_log_events(
                logGroupName=log_group,
                logStreamName=log_stream,
                logEvents=[
                    {"timestamp": now_utc(millis=True), "message": "test"},
                    {"timestamp": now_utc(millis=True), "message": "test 2"},
                ],
            )

        retry(put_event, retries=6, sleep=3.0)

        shard_iterator = kinesis_client.get_shard_iterator(
            StreamName=kinesis,
            ShardId="shardId-000000000000",
            ShardIteratorType="TRIM_HORIZON",
        )["ShardIterator"]

        response = kinesis_client.get_records(ShardIterator=shard_iterator)
        self.assertEqual(1, len(response["Records"]))

        # clean up
        self.cleanup(log_group, log_stream)
        kinesis_client.delete_stream(StreamName=kinesis, EnforceConsumerDeletion=True)

    def test_metric_filters(self):
        log_group = "g-%s" % short_uid()
        log_stream = "s-%s" % short_uid()
        filter_name = "f-%s" % short_uid()
        metric_ns = "ns-%s" % short_uid()
        metric_name = "metric1"
        transforms = {
            "metricNamespace": metric_ns,
            "metricName": metric_name,
            "metricValue": "1",
            "defaultValue": 123,
        }
        result = self.logs_client.put_metric_filter(
            logGroupName=log_group,
            filterName=filter_name,
            filterPattern="*",
            metricTransformations=[transforms],
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])

        result = self.logs_client.describe_metric_filters(
            logGroupName=log_group, filterNamePrefix="f-"
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        result = [mf for mf in result["metricFilters"] if mf["filterName"] == filter_name]
        self.assertEqual(1, len(result))

        # put log events and assert metrics being published
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        self.create_log_group_and_stream(log_group, log_stream)
        self.logs_client.put_log_events(
            logGroupName=log_group, logStreamName=log_stream, logEvents=events
        )

        # Get metric data
        cw_client = aws_stack.connect_to_service("cloudwatch")
        metric_data = cw_client.get_metric_data(
            MetricDataQueries=[
                {
                    "Id": "q1",
                    "MetricStat": {
                        "Metric": {"Namespace": metric_ns, "MetricName": metric_name},
                        "Period": 60,
                        "Stat": "Sum",
                    },
                }
            ],
            StartTime=datetime.utcnow() - timedelta(hours=1),
            EndTime=datetime.utcnow(),
        )["MetricDataResults"]
        self.assertEqual(1, len(metric_data))
        self.assertEqual([1], metric_data[0]["Values"])
        self.assertEqual("Complete", metric_data[0]["StatusCode"])

        # delete filters
        result = self.logs_client.delete_metric_filter(
            logGroupName=log_group, filterName=filter_name
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])

        result = self.logs_client.describe_metric_filters(
            logGroupName=log_group, filterNamePrefix="f-"
        )
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        result = [mf for mf in result["metricFilters"] if mf["filterName"] == filter_name]
        self.assertEqual(0, len(result))

    def create_log_group_and_stream(self, log_group, log_stream):
        response = self.logs_client.create_log_group(logGroupName=log_group)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])
        response = self.logs_client.create_log_stream(
            logGroupName=log_group, logStreamName=log_stream
        )
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def cleanup(self, log_group, log_stream):
        self.logs_client.delete_log_stream(logGroupName=log_group, logStreamName=log_stream)
        self.logs_client.delete_log_group(logGroupName=log_group)
