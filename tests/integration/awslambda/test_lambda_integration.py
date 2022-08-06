import base64
import json
import os
import time
from unittest.mock import patch

import pytest
from botocore.exceptions import ClientError

from localstack import config
from localstack.services.apigateway.helpers import path_based_url
from localstack.services.awslambda.lambda_api import (
    BATCH_SIZE_RANGES,
    INVALID_PARAMETER_VALUE_EXCEPTION,
)
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_NODEJS14X,
    LAMBDA_RUNTIME_PYTHON36,
    LAMBDA_RUNTIME_PYTHON37,
)
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, safe_requests, short_uid
from localstack.utils.strings import to_bytes
from localstack.utils.sync import poll_condition
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events

from .functions import lambda_integration
from .test_lambda import (
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_NODEJS_APIGW_502,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
)

TEST_STAGE_NAME = "testing"
TEST_SNS_TOPIC_NAME = "sns-topic-1"

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PARALLEL_FILE = os.path.join(THIS_FOLDER, "functions", "lambda_parallel.py")

lambda_role = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
s3_lambda_permission = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "sqs:*",
                "dynamodb:DescribeStream",
                "dynamodb:GetRecords",
                "dynamodb:GetShardIterator",
                "dynamodb:ListStreams",
                "kinesis:DescribeStream",
                "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:ListShards",
                "kinesis:ListStreams",
                "kinesis:SubscribeToShard",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
            ],
            "Resource": ["*"],
        }
    ],
}


class TestSQSEventSourceMapping:
    # FIXME: refactor and move to test_lambda_sqs_integration

    @pytest.mark.skip_snapshot_verify
    def test_event_source_mapping_default_batch_size(
        self,
        create_lambda_function,
        lambda_client,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        dynamodb_client,
        dynamodb_create_table,
        lambda_su_role,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.lambda_api())
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}-1"
        queue_name_2 = f"queue-{short_uid()}-2"
        queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
        queue_arn_1 = sqs_queue_arn(queue_url_1)

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )

            rs = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1, FunctionName=function_name
            )
            snapshot.match("create-event-source-mapping", rs)

            uuid = rs["UUID"]
            assert BATCH_SIZE_RANGES["sqs"][0] == rs["BatchSize"]
            _await_event_source_mapping_enabled(lambda_client, uuid)

            with pytest.raises(ClientError) as e:
                # Update batch size with invalid value
                rs = lambda_client.update_event_source_mapping(
                    UUID=uuid,
                    FunctionName=function_name,
                    BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
                )
            snapshot.match("invalid-update-event-source-mapping", e.value.response)
            e.match(INVALID_PARAMETER_VALUE_EXCEPTION)

            queue_url_2 = sqs_create_queue(QueueName=queue_name_2)
            queue_arn_2 = sqs_queue_arn(queue_url_2)

            with pytest.raises(ClientError) as e:
                # Create event source mapping with invalid batch size value
                rs = lambda_client.create_event_source_mapping(
                    EventSourceArn=queue_arn_2,
                    FunctionName=function_name,
                    BatchSize=BATCH_SIZE_RANGES["sqs"][1] + 1,
                )
            snapshot.match("invalid-create-event-source-mapping", e.value.response)
            e.match(INVALID_PARAMETER_VALUE_EXCEPTION)
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    def test_sqs_event_source_mapping(
        self,
        create_lambda_function,
        lambda_client,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        logs_client,
        lambda_su_role,
    ):
        function_name = f"lambda_func-{short_uid()}"
        queue_name_1 = f"queue-{short_uid()}-1"
        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            queue_url_1 = sqs_create_queue(QueueName=queue_name_1)
            queue_arn_1 = sqs_queue_arn(queue_url_1)
            mapping_uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=queue_arn_1,
                FunctionName=function_name,
                MaximumBatchingWindowInSeconds=1,
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, mapping_uuid)

            sqs_client.send_message(QueueUrl=queue_url_1, MessageBody=json.dumps({"foo": "bar"}))

            retry(
                check_expected_lambda_log_events_length,
                retries=10,
                sleep=1,
                function_name=function_name,
                expected_length=1,
                logs_client=logs_client,
            )

            rs = sqs_client.receive_message(QueueUrl=queue_url_1)
            assert rs.get("Messages") is None
        finally:
            lambda_client.delete_event_source_mapping(UUID=mapping_uuid)


class TestDynamoDBEventSourceMapping:
    def test_dynamodb_event_source_mapping(
        self,
        lambda_client,
        create_lambda_function,
        create_iam_role_with_policy,
        dynamodb_client,
        dynamodb_create_table,
        logs_client,
        check_lambda_logs,
    ):
        def check_logs():
            expected = [
                r'.*"Records":.*',
                r'.*"dynamodb": {(.*)}.*',
                r'.*"eventSource": ("aws:dynamodb").*',
                r'.*"eventName": ("INSERT").*',
                r'.*"Keys": {0}.*'.format(json.dumps(db_item)),
            ]
            check_lambda_logs(function_name, expected_lines=expected)

        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"
        db_item = {partition_key: {"S": "hello world"}}
        try:
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=lambda_role,
                PolicyDefinition=s3_lambda_permission,
            )

            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON37,
                role=role_arn,
            )
            dynamodb_create_table(table_name=table_name, partition_key=partition_key)
            _await_dynamodb_table_active(dynamodb_client, table_name)
            stream_arn = dynamodb_client.update_table(
                TableName=table_name,
                StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
            )["TableDescription"]["LatestStreamArn"]
            event_source_uuid = lambda_client.create_event_source_mapping(
                FunctionName=function_name,
                BatchSize=1,
                StartingPosition="LATEST",
                EventSourceArn=stream_arn,
                MaximumBatchingWindowInSeconds=1,
                MaximumRetryAttempts=1,
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, event_source_uuid)

            dynamodb_client.put_item(TableName=table_name, Item=db_item)
            retry(check_logs, retries=50, sleep=2)
        finally:
            lambda_client.delete_event_source_mapping(UUID=event_source_uuid)

    def test_disabled_dynamodb_event_source_mapping(
        self,
        create_lambda_function,
        lambda_client,
        dynamodb_resource,
        dynamodb_client,
        dynamodb_create_table,
        logs_client,
        dynamodbstreams_client,
        lambda_su_role,
    ):
        def is_stream_enabled():
            return (
                dynamodbstreams_client.describe_stream(StreamArn=latest_stream_arn)[
                    "StreamDescription"
                ]["StreamStatus"]
                == "ENABLED"
            )

        function_name = f"lambda_func-{short_uid()}"
        ddb_table = f"ddb_table-{short_uid()}"
        items = [
            {"id": short_uid(), "data": "data1"},
            {"id": short_uid(), "data": "data2"},
        ]

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            latest_stream_arn = dynamodb_create_table(
                table_name=ddb_table, partition_key="id", stream_view_type="NEW_IMAGE"
            )["TableDescription"]["LatestStreamArn"]
            rs = lambda_client.create_event_source_mapping(
                FunctionName=function_name,
                EventSourceArn=latest_stream_arn,
                StartingPosition="TRIM_HORIZON",
                MaximumBatchingWindowInSeconds=1,
            )
            uuid = rs["UUID"]
            _await_event_source_mapping_enabled(lambda_client, uuid)

            assert poll_condition(is_stream_enabled, timeout=30)
            table = dynamodb_resource.Table(ddb_table)

            table.put_item(Item=items[0])
            # Lambda should be invoked 1 time
            retry(
                check_expected_lambda_log_events_length,
                retries=10,
                sleep=3,
                function_name=function_name,
                expected_length=1,
                logs_client=logs_client,
            )
            # disable event source mapping
            lambda_client.update_event_source_mapping(UUID=uuid, Enabled=False)
            time.sleep(2)
            table.put_item(Item=items[1])
            # lambda no longer invoked, still have 1 event
            check_expected_lambda_log_events_length(
                expected_length=1, function_name=function_name, logs_client=logs_client
            )
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    # TODO invalid test against AWS, this behavior just is not correct
    def test_deletion_event_source_mapping_with_dynamodb(
        self, create_lambda_function, lambda_client, dynamodb_client, lambda_su_role
    ):
        try:
            function_name = f"lambda_func-{short_uid()}"
            ddb_table = f"ddb_table-{short_uid()}"

            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            latest_stream_arn = aws_stack.create_dynamodb_table(
                table_name=ddb_table,
                partition_key="id",
                client=dynamodb_client,
                stream_view_type="NEW_IMAGE",
            )["TableDescription"]["LatestStreamArn"]
            result = lambda_client.create_event_source_mapping(
                FunctionName=function_name,
                EventSourceArn=latest_stream_arn,
                StartingPosition="TRIM_HORIZON",
            )
            event_source_mapping_uuid = result["UUID"]
            _await_dynamodb_table_active(dynamodb_client, ddb_table)
            dynamodb_client.delete_table(TableName=ddb_table)
            result = lambda_client.list_event_source_mappings(EventSourceArn=latest_stream_arn)
            assert 1 == len(result["EventSourceMappings"])
        finally:
            lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)

    def test_dynamodb_event_source_mapping_with_on_failure_destination_config(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_queue_arn,
        sqs_create_queue,
        create_iam_role_with_policy,
        dynamodb_client,
        dynamodb_create_table,
    ):
        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"
        item = {partition_key: {"S": "hello world"}}

        try:
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=lambda_role,
                PolicyDefinition=s3_lambda_permission,
            )

            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON37,
                role=role_arn,
            )
            dynamodb_create_table(table_name=table_name, partition_key=partition_key)
            _await_dynamodb_table_active(dynamodb_client, table_name)
            result = dynamodb_client.update_table(
                TableName=table_name,
                StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
            )
            stream_arn = result["TableDescription"]["LatestStreamArn"]
            destination_queue = sqs_create_queue()
            queue_failure_event_source_mapping_arn = sqs_queue_arn(destination_queue)
            destination_config = {
                "OnFailure": {"Destination": queue_failure_event_source_mapping_arn}
            }
            result = lambda_client.create_event_source_mapping(
                FunctionName=function_name,
                BatchSize=1,
                StartingPosition="LATEST",
                EventSourceArn=stream_arn,
                MaximumBatchingWindowInSeconds=1,
                MaximumRetryAttempts=1,
                DestinationConfig=destination_config,
            )
            event_source_mapping_uuid = result["UUID"]
            _await_event_source_mapping_enabled(lambda_client, event_source_mapping_uuid)

            dynamodb_client.put_item(TableName=table_name, Item=item)

            def verify_failure_received():
                res = sqs_client.receive_message(QueueUrl=destination_queue)
                msg = res["Messages"][0]
                body = json.loads(msg["Body"])
                assert body["requestContext"]["condition"] == "RetryAttemptsExhausted"
                assert body["DDBStreamBatchInfo"]["batchSize"] == 1
                assert body["DDBStreamBatchInfo"]["streamArn"] in stream_arn

            retry(verify_failure_received, retries=5, sleep=5, sleep_before=5)
        finally:
            lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)


class TestLambdaHttpInvocation:
    def test_http_invocation_with_apigw_proxy(self, create_lambda_function):
        lambda_name = f"test_lambda_{short_uid()}"
        lambda_resource = "/api/v1/{proxy+}"
        lambda_path = "/api/v1/hello/world"
        lambda_request_context_path = "/" + TEST_STAGE_NAME + lambda_path
        lambda_request_context_resource_path = lambda_resource

        create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
        )

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = f"arn:aws:apigateway:{aws_stack.get_region()}:lambda:path/2015-03-31/functions/{lambda_uri}/invocations"
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

        assert lambda_path == content["path"]
        assert lambda_resource == content["resource"]
        assert lambda_request_context_path == content["requestContext"]["path"]
        assert lambda_request_context_resource_path == content["requestContext"]["resourcePath"]

    def test_malformed_response_apigw_invocation(self, create_lambda_function, lambda_client):
        lambda_name = f"test_lambda_{short_uid()}"
        lambda_resource = "/api/v1/{proxy+}"
        lambda_path = "/api/v1/hello/world"

        create_lambda_function(
            func_name=lambda_name,
            zip_file=testutil.create_zip_file(TEST_LAMBDA_NODEJS_APIGW_502, get_content=True),
            runtime=LAMBDA_RUNTIME_NODEJS14X,
            handler="apigw_502.handler",
        )

        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = f"arn:aws:apigateway:{aws_stack.get_region()}:lambda:path/2015-03-31/functions/{lambda_uri}/invocations"
        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            "test_gateway",
            target_uri,
            path=lambda_resource,
            stage_name=TEST_STAGE_NAME,
        )
        api_id = result["id"]
        url = path_based_url(api_id=api_id, stage_name=TEST_STAGE_NAME, path=lambda_path)
        result = safe_requests.get(url)

        assert result.status_code == 502
        assert result.headers.get("Content-Type") == "application/json"
        assert json.loads(result.content)["message"] == "Internal server error"


class TestKinesisSource:
    def test_create_kinesis_event_source_mapping(
        self,
        create_lambda_function,
        lambda_client,
        kinesis_client,
        kinesis_create_stream,
        lambda_su_role,
        wait_for_stream_ready,
        logs_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        record_data = "hello"
        num_events_kinesis = 10

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )

            kinesis_create_stream(StreamName=stream_name, ShardCount=1)
            wait_for_stream_ready(stream_name=stream_name)
            stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
            assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
            stream_arn = kinesis_client.describe_stream(StreamName=stream_name)[
                "StreamDescription"
            ]["StreamARN"]

            uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=stream_arn, FunctionName=function_name, StartingPosition="LATEST"
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, uuid)
            kinesis_client.put_records(
                Records=[
                    {"Data": record_data, "PartitionKey": f"test_{i}"}
                    for i in range(0, num_events_kinesis)
                ],
                StreamName=stream_name,
            )

            events = _get_lambda_invocation_events(
                logs_client, function_name, expected_num_events=1
            )
            records = events[0]["Records"]
            assert len(records) == num_events_kinesis
            for record in records:
                assert "eventID" in record
                assert "eventSourceARN" in record
                assert "eventSource" in record
                assert "eventVersion" in record
                assert "eventName" in record
                assert "invokeIdentityArn" in record
                assert "awsRegion" in record
                assert "kinesis" in record
                actual_record_data = base64.b64decode(record["kinesis"]["data"]).decode("utf-8")
                assert actual_record_data == record_data
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    @patch.object(config, "SYNCHRONOUS_KINESIS_EVENTS", False)
    def test_kinesis_event_source_mapping_with_async_invocation(
        self,
        lambda_client,
        kinesis_client,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        logs_client,
        lambda_su_role,
    ):
        # TODO: this test will fail if `log_cli=true` is set and `LAMBDA_EXECUTOR=local`!
        # apparently this particular configuration prevents lambda logs from being extracted properly, giving the
        # appearance that the function was never invoked.
        try:
            function_name = f"lambda_func-{short_uid()}"
            stream_name = f"test-foobar-{short_uid()}"
            num_records_per_batch = 10
            num_batches = 2

            create_lambda_function(
                handler_file=TEST_LAMBDA_PARALLEL_FILE,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            kinesis_create_stream(StreamName=stream_name, ShardCount=1)
            stream_arn = kinesis_client.describe_stream(StreamName=stream_name)[
                "StreamDescription"
            ]["StreamARN"]
            wait_for_stream_ready(stream_name=stream_name)
            stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
            assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1

            uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=stream_arn,
                FunctionName=function_name,
                StartingPosition="LATEST",
                BatchSize=num_records_per_batch,
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, uuid)

            for i in range(num_batches):
                start = time.perf_counter()
                kinesis_client.put_records(
                    Records=[
                        {"Data": json.dumps({"record_id": j}), "PartitionKey": f"test_{i}"}
                        for j in range(0, num_records_per_batch)
                    ],
                    StreamName=stream_name,
                )
                assert (time.perf_counter() - start) < 1  # this should not take more than a second

            invocation_events = _get_lambda_invocation_events(
                logs_client, function_name, expected_num_events=num_batches
            )
            for i in range(num_batches):
                event = invocation_events[i]
                assert len(event["event"]["Records"]) == num_records_per_batch
                actual_record_ids = []
                for record in event["event"]["Records"]:
                    assert "eventID" in record
                    assert "eventSourceARN" in record
                    assert "eventSource" in record
                    assert "eventVersion" in record
                    assert "eventName" in record
                    assert "invokeIdentityArn" in record
                    assert "awsRegion" in record
                    assert "kinesis" in record
                    record_data = base64.b64decode(record["kinesis"]["data"]).decode("utf-8")
                    actual_record_id = json.loads(record_data)["record_id"]
                    actual_record_ids.append(actual_record_id)
                actual_record_ids.sort()
                assert actual_record_ids == [i for i in range(num_records_per_batch)]

            assert (
                invocation_events[1]["executionStart"] - invocation_events[0]["executionStart"]
            ) > 5
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    def test_kinesis_event_source_trim_horizon(
        self,
        lambda_client,
        kinesis_client,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        logs_client,
        lambda_su_role,
    ):

        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10
        num_batches = 3

        try:
            create_lambda_function(
                handler_file=TEST_LAMBDA_PARALLEL_FILE,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            kinesis_create_stream(StreamName=stream_name, ShardCount=1)
            stream_arn = kinesis_client.describe_stream(StreamName=stream_name)[
                "StreamDescription"
            ]["StreamARN"]
            wait_for_stream_ready(stream_name=stream_name)
            stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
            assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1

            # insert some records before event source mapping created
            for i in range(num_batches - 1):
                kinesis_client.put_records(
                    Records=[
                        {"Data": json.dumps({"record_id": j}), "PartitionKey": f"test_{i}"}
                        for j in range(0, num_records_per_batch)
                    ],
                    StreamName=stream_name,
                )
            uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=stream_arn,
                FunctionName=function_name,
                StartingPosition="TRIM_HORIZON",
                BatchSize=num_records_per_batch,
            )["UUID"]
            # insert some more records
            kinesis_client.put_records(
                Records=[
                    {"Data": json.dumps({"record_id": i}), "PartitionKey": f"test_{num_batches}"}
                    for i in range(0, num_records_per_batch)
                ],
                StreamName=stream_name,
            )

            invocation_events = _get_lambda_invocation_events(
                logs_client, function_name, expected_num_events=num_batches
            )
            for i in range(num_batches):
                event = invocation_events[i]
                assert len(event["event"]["Records"]) == num_records_per_batch
                actual_record_ids = []
                for record in event["event"]["Records"]:
                    assert "eventID" in record
                    assert "eventSourceARN" in record
                    assert "eventSource" in record
                    assert "eventVersion" in record
                    assert "eventName" in record
                    assert "invokeIdentityArn" in record
                    assert "awsRegion" in record
                    assert "kinesis" in record
                    record_data = base64.b64decode(record["kinesis"]["data"]).decode("utf-8")
                    actual_record_id = json.loads(record_data)["record_id"]
                    actual_record_ids.append(actual_record_id)

                actual_record_ids.sort()
                assert actual_record_ids == [i for i in range(num_records_per_batch)]
        finally:
            lambda_client.delete_event_source_mapping(UUID=uuid)

    def test_disable_kinesis_event_source_mapping(
        self,
        lambda_client,
        kinesis_client,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        logs_client,
        lambda_su_role,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10

        try:
            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON36,
                role=lambda_su_role,
            )
            kinesis_create_stream(StreamName=stream_name, ShardCount=1)
            stream_arn = kinesis_client.describe_stream(StreamName=stream_name)[
                "StreamDescription"
            ]["StreamARN"]
            wait_for_stream_ready(stream_name=stream_name)
            event_source_uuid = lambda_client.create_event_source_mapping(
                EventSourceArn=stream_arn,
                FunctionName=function_name,
                StartingPosition="LATEST",
                BatchSize=num_records_per_batch,
            )["UUID"]
            _await_event_source_mapping_enabled(lambda_client, event_source_uuid)

            kinesis_client.put_records(
                Records=[
                    {"Data": json.dumps({"record_id": i}), "PartitionKey": "test"}
                    for i in range(0, num_records_per_batch)
                ],
                StreamName=stream_name,
            )

            events = _get_lambda_invocation_events(
                logs_client, function_name, expected_num_events=1
            )
            assert len(events) == 1

            lambda_client.update_event_source_mapping(UUID=event_source_uuid, Enabled=False)
            time.sleep(2)
            kinesis_client.put_records(
                Records=[
                    {"Data": json.dumps({"record_id": i}), "PartitionKey": "test"}
                    for i in range(0, num_records_per_batch)
                ],
                StreamName=stream_name,
            )
            time.sleep(7)  # wait for records to pass through stream
            # should still only get the first batch from before mapping was disabled
            events = _get_lambda_invocation_events(
                logs_client, function_name, expected_num_events=1
            )
            assert len(events) == 1
        finally:
            lambda_client.delete_event_source_mapping(UUID=event_source_uuid)

    def test_kinesis_event_source_mapping_with_on_failure_destination_config(
        self,
        lambda_client,
        create_lambda_function,
        sqs_client,
        sqs_queue_arn,
        sqs_create_queue,
        create_iam_role_with_policy,
        kinesis_client,
        wait_for_stream_ready,
    ):
        try:
            function_name = f"lambda_func-{short_uid()}"
            role = f"test-lambda-role-{short_uid()}"
            policy_name = f"test-lambda-policy-{short_uid()}"
            kinesis_name = f"test-kinesis-{short_uid()}"
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=lambda_role,
                PolicyDefinition=s3_lambda_permission,
            )

            create_lambda_function(
                handler_file=TEST_LAMBDA_PYTHON,
                func_name=function_name,
                runtime=LAMBDA_RUNTIME_PYTHON37,
                role=role_arn,
            )
            kinesis_client.create_stream(StreamName=kinesis_name, ShardCount=1)
            result = kinesis_client.describe_stream(StreamName=kinesis_name)["StreamDescription"]
            kinesis_arn = result["StreamARN"]
            wait_for_stream_ready(stream_name=kinesis_name)
            queue_event_source_mapping = sqs_create_queue()
            destination_queue = sqs_queue_arn(queue_event_source_mapping)
            destination_config = {"OnFailure": {"Destination": destination_queue}}
            message = {
                "input": "hello",
                "value": "world",
                lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
            }

            result = lambda_client.create_event_source_mapping(
                FunctionName=function_name,
                BatchSize=1,
                StartingPosition="LATEST",
                EventSourceArn=kinesis_arn,
                MaximumBatchingWindowInSeconds=1,
                MaximumRetryAttempts=1,
                DestinationConfig=destination_config,
            )
            event_source_mapping_uuid = result["UUID"]
            _await_event_source_mapping_enabled(lambda_client, event_source_mapping_uuid)
            kinesis_client.put_record(
                StreamName=kinesis_name, Data=to_bytes(json.dumps(message)), PartitionKey="custom"
            )

            def verify_failure_received():
                result = sqs_client.receive_message(QueueUrl=queue_event_source_mapping)
                msg = result["Messages"][0]
                body = json.loads(msg["Body"])
                assert body["requestContext"]["condition"] == "RetryAttemptsExhausted"
                assert body["KinesisBatchInfo"]["batchSize"] == 1
                assert body["KinesisBatchInfo"]["streamArn"] == kinesis_arn

            retry(verify_failure_received, retries=50, sleep=5, sleep_before=5)

        finally:
            kinesis_client.delete_stream(StreamName=kinesis_name, EnforceConsumerDeletion=True)
            lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)


def _await_event_source_mapping_enabled(lambda_client, uuid, retries=30):
    def assert_mapping_enabled():
        assert lambda_client.get_event_source_mapping(UUID=uuid)["State"] == "Enabled"

    retry(assert_mapping_enabled, sleep_before=2, retries=retries)


def _await_dynamodb_table_active(dynamodb_client, table_name, retries=6):
    def assert_table_active():
        assert (
            dynamodb_client.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE"
        )

    retry(assert_table_active, retries=retries, sleep_before=2)


def _get_lambda_invocation_events(logs_client, function_name, expected_num_events, retries=30):
    def get_events():
        events = get_lambda_log_events(function_name, logs_client=logs_client)
        assert len(events) == expected_num_events
        return events

    return retry(get_events, retries=retries, sleep_before=2)
