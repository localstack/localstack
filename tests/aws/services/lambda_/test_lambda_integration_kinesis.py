import json
import math
import os
import time
from unittest.mock import patch

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import (
    _await_event_source_mapping_enabled,
    _await_event_source_mapping_state,
    _get_lambda_invocation_events,
    is_new_provider,
    is_old_provider,
    lambda_role,
    s3_lambda_permission,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import retry
from tests.aws.services.lambda_.functions import lambda_integration
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_PYTHON_ECHO

TEST_LAMBDA_PARALLEL_FILE = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "functions", "lambda_parallel.py"
)


@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.key_value("sequenceNumber"))
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformer(
        KeyValueBasedTransformer(
            lambda k, v: str(v) if k == "executionStart" else None,
            "<execution-start>",
            replace_reference=False,
        )
    )


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Records..eventID",
        "$..Records..kinesis.kinesisSchemaVersion",
        "$..BisectBatchOnFunctionError",
        "$..DestinationConfig",
        "$..FunctionResponseTypes",
        "$..LastProcessingResult",
        "$..MaximumBatchingWindowInSeconds",
        "$..MaximumRecordAgeInSeconds",
        "$..ResponseMetadata.HTTPStatusCode",
        "$..State",
        "$..Topics",
        "$..TumblingWindowInSeconds",
    ],
)
class TestKinesisSource:
    @markers.aws.validated
    def test_create_kinesis_event_source_mapping(
        self,
        create_lambda_function,
        kinesis_create_stream,
        lambda_su_role,
        wait_for_stream_ready,
        cleanups,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        record_data = "hello"
        num_events_kinesis = 10

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            EventSourceArn=stream_arn, FunctionName=function_name, StartingPosition="LATEST"
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        def _send_and_receive_messages():
            aws_client.kinesis.put_records(
                Records=[
                    {"Data": record_data, "PartitionKey": f"test_{i}"}
                    for i in range(0, num_events_kinesis)
                ],
                StreamName=stream_name,
            )

            return _get_lambda_invocation_events(
                aws_client.logs, function_name, expected_num_events=1, retries=5
            )

        # need to retry here in case the LATEST StartingPosition of the event source mapping does not catch records
        events = retry(_send_and_receive_messages, retries=3)
        records = events[0]
        snapshot.match("kinesis_records", records)
        # check if the timestamp has the correct format
        timestamp = events[0]["Records"][0]["kinesis"]["approximateArrivalTimestamp"]
        # check if the timestamp has same amount of numbers before the comma as the current timestamp
        # this will fail in november 2286, if this code is still around by then, read this comment and update to 10
        assert int(math.log10(timestamp)) == 9

    # FIXME remove usage of this config value with 2.0
    @patch.object(config, "SYNCHRONOUS_KINESIS_EVENTS", False)
    @markers.aws.validated
    @pytest.mark.skipif(
        condition=is_new_provider(), reason="deprecated config that only works in legacy provider"
    )
    def test_kinesis_event_source_mapping_with_async_invocation(
        self,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        lambda_su_role,
        cleanups,
        snapshot,
        aws_client,
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
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1

        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="LATEST",
            BatchSize=num_records_per_batch,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        def _send_and_receive_messages():
            for i in range(num_batches):
                start = time.perf_counter()
                aws_client.kinesis.put_records(
                    Records=[
                        {"Data": json.dumps({"record_id": j}), "PartitionKey": f"test_{i}"}
                        for j in range(0, num_records_per_batch)
                    ],
                    StreamName=stream_name,
                )
                assert (time.perf_counter() - start) < 1  # this should not take more than a second

            return _get_lambda_invocation_events(
                aws_client.logs, function_name, expected_num_events=num_batches, retries=5
            )

        # need to retry here in case the LATEST StartingPosition of the event source mapping does not catch records
        invocation_events = retry(_send_and_receive_messages, retries=3)
        snapshot.match("invocation_events", invocation_events)

        assert (invocation_events[1]["executionStart"] - invocation_events[0]["executionStart"]) > 5

    @markers.aws.validated
    def test_kinesis_event_source_trim_horizon(
        self,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        lambda_su_role,
        cleanups,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10
        num_batches = 3

        create_lambda_function(
            handler_file=TEST_LAMBDA_PARALLEL_FILE,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1

        # insert some records before event source mapping created
        for i in range(num_batches - 1):
            aws_client.kinesis.put_records(
                Records=[
                    {"Data": json.dumps({"record_id": j}), "PartitionKey": f"test_{i}"}
                    for j in range(0, num_records_per_batch)
                ],
                StreamName=stream_name,
            )
        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
            BatchSize=num_records_per_batch,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        # insert some more records
        aws_client.kinesis.put_records(
            Records=[
                {"Data": json.dumps({"record_id": i}), "PartitionKey": f"test_{num_batches}"}
                for i in range(0, num_records_per_batch)
            ],
            StreamName=stream_name,
        )

        invocation_events = _get_lambda_invocation_events(
            aws_client.logs, function_name, expected_num_events=num_batches
        )
        snapshot.match("invocation_events", invocation_events)

    @markers.aws.validated
    def test_disable_kinesis_event_source_mapping(
        self,
        create_lambda_function,
        kinesis_create_stream,
        wait_for_stream_ready,
        lambda_su_role,
        cleanups,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]
        wait_for_stream_ready(stream_name=stream_name)
        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="LATEST",
            BatchSize=num_records_per_batch,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_uuid)
        )
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_uuid)

        def _send_and_receive_messages():
            aws_client.kinesis.put_records(
                Records=[
                    {"Data": json.dumps({"record_id": i}), "PartitionKey": "test"}
                    for i in range(0, num_records_per_batch)
                ],
                StreamName=stream_name,
            )

            return _get_lambda_invocation_events(
                aws_client.logs, function_name, expected_num_events=1, retries=10
            )

        invocation_events = retry(_send_and_receive_messages, retries=3)
        snapshot.match("invocation_events", invocation_events)

        aws_client.lambda_.update_event_source_mapping(UUID=event_source_uuid, Enabled=False)
        _await_event_source_mapping_state(aws_client.lambda_, event_source_uuid, state="Disabled")
        # we need to wait here, so the event source mapping is for sure disabled, sadly the state is no real indication
        if is_aws_cloud():
            time.sleep(60)
        aws_client.kinesis.put_records(
            Records=[
                {"Data": json.dumps({"record_id_disabled": i}), "PartitionKey": "test"}
                for i in range(0, num_records_per_batch)
            ],
            StreamName=stream_name,
        )
        time.sleep(7)  # wait for records to pass through stream
        # should still only get the first batch from before mapping was disabled
        _get_lambda_invocation_events(
            aws_client.logs, function_name, expected_num_events=1, retries=10
        )

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.KinesisBatchInfo.approximateArrivalOfFirstRecord",
            "$..Messages..Body.KinesisBatchInfo.approximateArrivalOfLastRecord",
            "$..Messages..Body.KinesisBatchInfo.shardId",
            "$..Messages..Body.KinesisBatchInfo.streamArn",
            "$..Messages..Body.requestContext.approximateInvokeCount",
            "$..Messages..Body.responseContext.statusCode",
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.requestContext.functionArn",
            # destination config arn missing, which leads to those having wrong resource ids
            "$..EventSourceArn",
            "$..FunctionArn",
        ],
        condition=is_old_provider,
    )
    @markers.aws.validated
    def test_kinesis_event_source_mapping_with_on_failure_destination_config(
        self,
        create_lambda_function,
        sqs_get_queue_arn,
        sqs_create_queue,
        create_iam_role_with_policy,
        wait_for_stream_ready,
        cleanups,
        snapshot,
        aws_client,
    ):
        # snapshot setup
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))
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
            runtime=Runtime.python3_9,
            role=role_arn,
        )
        aws_client.kinesis.create_stream(StreamName=kinesis_name, ShardCount=1)
        cleanups.append(
            lambda: aws_client.kinesis.delete_stream(
                StreamName=kinesis_name, EnforceConsumerDeletion=True
            )
        )
        result = aws_client.kinesis.describe_stream(StreamName=kinesis_name)["StreamDescription"]
        kinesis_arn = result["StreamARN"]
        wait_for_stream_ready(stream_name=kinesis_name)
        queue_event_source_mapping = sqs_create_queue()
        destination_queue = sqs_get_queue_arn(queue_event_source_mapping)
        destination_config = {"OnFailure": {"Destination": destination_queue}}
        message = {
            "input": "hello",
            "value": "world",
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }

        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=kinesis_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
            DestinationConfig=destination_config,
        )
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)
        aws_client.kinesis.put_record(
            StreamName=kinesis_name, Data=to_bytes(json.dumps(message)), PartitionKey="custom"
        )

        def verify_failure_received():
            result = aws_client.sqs.receive_message(QueueUrl=queue_event_source_mapping)
            assert result["Messages"]
            return result

        sqs_payload = retry(verify_failure_received, retries=50, sleep=5, sleep_before=5)
        snapshot.match("sqs_payload", sqs_payload)
