import base64
import json
import os
import time
import unittest
from unittest.mock import patch

from botocore.exceptions import ClientError

from localstack import config
from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda import lambda_api
from localstack.services.awslambda.lambda_api import (
    BATCH_SIZE_RANGES,
    INVALID_PARAMETER_VALUE_EXCEPTION,
)
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, safe_requests, short_uid
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events

from .test_lambda import (
    TEST_LAMBDA_FUNCTION_PREFIX,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

TEST_STAGE_NAME = "testing"
TEST_SNS_TOPIC_NAME = "sns-topic-1"

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PARALLEL_FILE = os.path.join(THIS_FOLDER, "functions", "lambda_parallel.py")


class TestLambdaEventSourceMappings(unittest.TestCase):
    def test_event_source_mapping_default_batch_size(self):
        function_name = "lambda_func-{}".format(short_uid())
        queue_name_1 = "queue-{}-1".format(short_uid())
        queue_name_2 = "queue-{}-2".format(short_uid())
        ddb_table = "ddb_table-{}".format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        lambda_client = aws_stack.create_external_boto_client("lambda")

        sqs_client = aws_stack.create_external_boto_client("sqs")
        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        rs = lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn_1, FunctionName=function_name
        )
        self.assertEqual(BATCH_SIZE_RANGES["sqs"][0], rs["BatchSize"])
        uuid = rs["UUID"]

        try:
            # Update batch size with invalid value
            lambda_client.update_event_source_mapping(
                UUID=uuid,
                FunctionName=function_name,
                BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
            )
            self.fail("This call should not be successful as the batch size > MAX_BATCH_SIZE")

        except ClientError as e:
            self.assertEqual(INVALID_PARAMETER_VALUE_EXCEPTION, e.response["Error"]["Code"])

        queue_url_2 = sqs_client.create_queue(QueueName=queue_name_2)["QueueUrl"]
        queue_arn_2 = aws_stack.sqs_queue_arn(queue_name_2)

        try:
            # Create event source mapping with invalid batch size value
            lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_2,
                FunctionName=function_name,
                BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
            )
            self.fail("This call should not be successful as the batch size > MAX_BATCH_SIZE")

        except ClientError as e:
            self.assertEqual(INVALID_PARAMETER_VALUE_EXCEPTION, e.response["Error"]["Code"])

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key="id")[
            "TableDescription"
        ]["TableArn"]
        rs = lambda_client.create_event_source_mapping(
            EventSourceArn=table_arn, FunctionName=function_name
        )
        self.assertEqual(BATCH_SIZE_RANGES["dynamodb"][0], rs["BatchSize"])

        # clean up
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        dynamodb_client.delete_table(TableName=ddb_table)
        sqs_client.delete_queue(QueueUrl=queue_url_1)
        sqs_client.delete_queue(QueueUrl=queue_url_2)
        lambda_client.delete_function(FunctionName=function_name)

    def test_disabled_event_source_mapping_with_dynamodb(self):
        function_name = "lambda_func-{}".format(short_uid())
        ddb_table = "ddb_table-{}".format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key="id")[
            "TableDescription"
        ]["TableArn"]

        lambda_client = aws_stack.create_external_boto_client("lambda")

        rs = lambda_client.create_event_source_mapping(
            FunctionName=function_name, EventSourceArn=table_arn
        )
        uuid = rs["UUID"]

        dynamodb = aws_stack.connect_to_resource("dynamodb")
        table = dynamodb.Table(ddb_table)

        items = [
            {"id": short_uid(), "data": "data1"},
            {"id": short_uid(), "data": "data2"},
        ]

        table.put_item(Item=items[0])
        events = get_lambda_log_events(function_name)

        # lambda was invoked 1 time
        self.assertEqual(1, len(events[0]["Records"]))

        # disable event source mapping
        lambda_client.update_event_source_mapping(UUID=uuid, Enabled=False)

        table.put_item(Item=items[1])
        events = get_lambda_log_events(function_name)

        # lambda no longer invoked, still have 1 event
        self.assertEqual(1, len(events[0]["Records"]))

        # clean up
        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        dynamodb_client.delete_table(TableName=ddb_table)

        lambda_client.delete_function(FunctionName=function_name)

    def test_deletion_event_source_mapping_with_dynamodb(self):
        function_name = "lambda_func-{}".format(short_uid())
        ddb_table = "ddb_table-{}".format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        table_arn = aws_stack.create_dynamodb_table(ddb_table, partition_key="id")[
            "TableDescription"
        ]["TableArn"]
        lambda_client = aws_stack.create_external_boto_client("lambda")

        lambda_client.create_event_source_mapping(
            FunctionName=function_name, EventSourceArn=table_arn
        )

        dynamodb_client = aws_stack.create_external_boto_client("dynamodb")
        dynamodb_client.delete_table(TableName=ddb_table)

        result = lambda_client.list_event_source_mappings(EventSourceArn=table_arn)
        self.assertEqual(0, len(result["EventSourceMappings"]))
        # clean up
        lambda_client.delete_function(FunctionName=function_name)

    def test_event_source_mapping_with_sqs(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        sqs_client = aws_stack.create_external_boto_client("sqs")

        function_name = "lambda_func-{}".format(short_uid())
        queue_name_1 = "queue-{}-1".format(short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        queue_url_1 = sqs_client.create_queue(QueueName=queue_name_1)["QueueUrl"]
        queue_arn_1 = aws_stack.sqs_queue_arn(queue_name_1)

        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn_1, FunctionName=function_name
        )

        sqs_client.send_message(QueueUrl=queue_url_1, MessageBody=json.dumps({"foo": "bar"}))
        events = retry(get_lambda_log_events, sleep_before=3, function_name=function_name)

        # lambda was invoked 1 time
        self.assertEqual(1, len(events[0]["Records"]))
        rs = sqs_client.receive_message(QueueUrl=queue_url_1)
        self.assertIsNone(rs.get("Messages"))

        # clean up
        sqs_client.delete_queue(QueueUrl=queue_url_1)
        lambda_client.delete_function(FunctionName=function_name)

    def test_create_kinesis_event_source_mapping(self):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        arn = aws_stack.kinesis_stream_arn(stream_name, account_id="000000000000")

        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_client.create_event_source_mapping(EventSourceArn=arn, FunctionName=function_name)

        def process_records(record):
            assert record

        aws_stack.create_kinesis_stream(stream_name, delete=True)
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            wait_until_started=True,
        )

        kinesis = aws_stack.create_external_boto_client("kinesis")
        stream_summary = kinesis.describe_stream_summary(StreamName=stream_name)
        self.assertEqual(1, stream_summary["StreamDescriptionSummary"]["OpenShardCount"])
        num_events_kinesis = 10
        kinesis.put_records(
            Records=[
                {"Data": "{}", "PartitionKey": "test_%s" % i} for i in range(0, num_events_kinesis)
            ],
            StreamName=stream_name,
        )

        events = get_lambda_log_events(function_name)
        self.assertEqual(10, len(events[0]["Records"]))

        self.assertIn("eventID", events[0]["Records"][0])
        self.assertIn("eventSourceARN", events[0]["Records"][0])
        self.assertIn("eventSource", events[0]["Records"][0])
        self.assertIn("eventVersion", events[0]["Records"][0])
        self.assertIn("eventName", events[0]["Records"][0])
        self.assertIn("invokeIdentityArn", events[0]["Records"][0])
        self.assertIn("awsRegion", events[0]["Records"][0])
        self.assertIn("kinesis", events[0]["Records"][0])

    def test_python_lambda_subscribe_sns_topic(self):
        sns_client = aws_stack.create_external_boto_client("sns")
        function_name = "{}-{}".format(TEST_LAMBDA_FUNCTION_PREFIX, short_uid())

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        topic = sns_client.create_topic(Name=TEST_SNS_TOPIC_NAME)
        topic_arn = topic["TopicArn"]

        sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=lambda_api.func_arn(function_name),
        )

        subject = "[Subject] Test subject"
        message = "Hello world."
        sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)

        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter="Records.*Sns",
        )
        notification = events[0]["Records"][0]["Sns"]

        self.assertIn("Subject", notification)
        self.assertEqual(subject, notification["Subject"])


class TestLambdaHttpInvocation(unittest.TestCase):
    def test_http_invocation_with_apigw_proxy(self):
        lambda_name = "test_lambda_%s" % short_uid()
        lambda_resource = "/api/v1/{proxy+}"
        lambda_path = "/api/v1/hello/world"
        lambda_request_context_path = "/" + TEST_STAGE_NAME + lambda_path
        lambda_request_context_resource_path = lambda_resource

        # create lambda function
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
            func_name=lambda_name,
        )

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        invocation_uri = "arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations"
        target_uri = invocation_uri % (aws_stack.get_region(), lambda_uri)

        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway2",
            target_uri,
            path=lambda_resource,
            stage_name=TEST_STAGE_NAME,
        )

        api_id = result["id"]
        url = path_based_url(api_id=api_id, stage_name=TEST_STAGE_NAME, path=lambda_path)
        result = safe_requests.post(
            url, data=b"{}", headers={"User-Agent": "python-requests/testing"}
        )
        content = json.loads(result.content)

        self.assertEqual(lambda_path, content["path"])
        self.assertEqual(lambda_resource, content["resource"])
        self.assertEqual(lambda_request_context_path, content["requestContext"]["path"])
        self.assertEqual(
            lambda_request_context_resource_path,
            content["requestContext"]["resourcePath"],
        )

        # clean up
        testutil.delete_lambda_function(lambda_name)


class TestKinesisSource:
    @patch.object(config, "SYNCHRONOUS_KINESIS_EVENTS", False)
    def test_kinesis_lambda_parallelism(self, lambda_client, kinesis_client):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PARALLEL_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        arn = aws_stack.kinesis_stream_arn(stream_name, account_id="000000000000")

        lambda_client.create_event_source_mapping(EventSourceArn=arn, FunctionName=function_name)

        def process_records(record):
            assert record

        aws_stack.create_kinesis_stream(stream_name, delete=True)
        kinesis_connector.listen_to_kinesis(
            stream_name=stream_name,
            listener_func=process_records,
            wait_until_started=True,
        )

        kinesis = aws_stack.create_external_boto_client("kinesis")
        stream_summary = kinesis.describe_stream_summary(StreamName=stream_name)
        assert 1 == stream_summary["StreamDescriptionSummary"]["OpenShardCount"]
        num_events_kinesis = 10
        # assure async call
        start = time.perf_counter()
        kinesis.put_records(
            Records=[
                {"Data": '{"batch": 0}', "PartitionKey": "test_%s" % i}
                for i in range(0, num_events_kinesis)
            ],
            StreamName=stream_name,
        )
        assert (time.perf_counter() - start) < 1  # this should not take more than a second
        kinesis.put_records(
            Records=[
                {"Data": '{"batch": 1}', "PartitionKey": "test_%s" % i}
                for i in range(0, num_events_kinesis)
            ],
            StreamName=stream_name,
        )

        def get_events():
            events = get_lambda_log_events(function_name, regex_filter=r"event.*Records")
            assert len(events) == 2
            return events

        events = retry(get_events, retries=5)

        def assertEvent(event, batch_no):
            assert 10 == len(event["event"]["Records"])

            assert "eventID" in event["event"]["Records"][0]
            assert "eventSourceARN" in event["event"]["Records"][0]
            assert "eventSource" in event["event"]["Records"][0]
            assert "eventVersion" in event["event"]["Records"][0]
            assert "eventName" in event["event"]["Records"][0]
            assert "invokeIdentityArn" in event["event"]["Records"][0]
            assert "awsRegion" in event["event"]["Records"][0]
            assert "kinesis" in event["event"]["Records"][0]

            assert {"batch": batch_no} == json.loads(
                base64.b64decode(event["event"]["Records"][0]["kinesis"]["data"]).decode(
                    config.DEFAULT_ENCODING
                )
            )

        assertEvent(events[0], 0)
        assertEvent(events[1], 1)

        assert (events[1]["executionStart"] - events[0]["executionStart"]) > 5

        # cleanup
        lambda_client.delete_function(FunctionName=function_name)
        kinesis_client.delete_stream(StreamName=stream_name)
