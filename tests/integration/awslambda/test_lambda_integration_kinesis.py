import base64
import json
import os
import time
from unittest.mock import patch

from localstack import config
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON39,
)
from localstack.testing.aws.lambda_utils import (
    _await_event_source_mapping_enabled,
    _get_lambda_invocation_events,
    lambda_role,
    s3_lambda_permission,
)
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import retry
from tests.integration.awslambda.functions import lambda_integration
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_PYTHON_ECHO

TEST_LAMBDA_PARALLEL_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "functions", "lambda_parallel.py"
)


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
        cleanups,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        record_data = "hello"
        num_events_kinesis = 10

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=lambda_su_role,
        )

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]

        uuid = lambda_client.create_event_source_mapping(
            EventSourceArn=stream_arn, FunctionName=function_name, StartingPosition="LATEST"
        )["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(lambda_client, uuid)
        kinesis_client.put_records(
            Records=[
                {"Data": record_data, "PartitionKey": f"test_{i}"}
                for i in range(0, num_events_kinesis)
            ],
            StreamName=stream_name,
        )

        events = _get_lambda_invocation_events(logs_client, function_name, expected_num_events=1)
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
        cleanups,
    ):
        # TODO: this test will fail if `log_cli=true` is set and `LAMBDA_EXECUTOR=local`!
        # apparently this particular configuration prevents lambda logs from being extracted properly, giving the
        # appearance that the function was never invoked.
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10
        num_batches = 2

        create_lambda_function(
            handler_file=TEST_LAMBDA_PARALLEL_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = kinesis_client.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1

        uuid = lambda_client.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="LATEST",
            BatchSize=num_records_per_batch,
        )["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))
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

        assert (invocation_events[1]["executionStart"] - invocation_events[0]["executionStart"]) > 5

    def test_kinesis_event_source_trim_horizon(
        self,
        lambda_client,
        kinesis_client,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        logs_client,
        lambda_su_role,
        cleanups,
    ):

        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10
        num_batches = 3

        create_lambda_function(
            handler_file=TEST_LAMBDA_PARALLEL_FILE,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
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
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))
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

    def test_disable_kinesis_event_source_mapping(
        self,
        lambda_client,
        kinesis_client,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        logs_client,
        lambda_su_role,
        cleanups,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = kinesis_client.describe_stream(StreamName=stream_name)["StreamDescription"][
            "StreamARN"
        ]
        wait_for_stream_ready(stream_name=stream_name)
        event_source_uuid = lambda_client.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="LATEST",
            BatchSize=num_records_per_batch,
        )["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=event_source_uuid))
        _await_event_source_mapping_enabled(lambda_client, event_source_uuid)

        kinesis_client.put_records(
            Records=[
                {"Data": json.dumps({"record_id": i}), "PartitionKey": "test"}
                for i in range(0, num_records_per_batch)
            ],
            StreamName=stream_name,
        )

        events = _get_lambda_invocation_events(logs_client, function_name, expected_num_events=1)
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
        events = _get_lambda_invocation_events(logs_client, function_name, expected_num_events=1)
        assert len(events) == 1

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
        cleanups,
    ):
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
        cleanups.append(
            lambda: kinesis_client.delete_stream(
                StreamName=kinesis_name, EnforceConsumerDeletion=True
            )
        )
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
        cleanups.append(
            lambda: lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)
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
