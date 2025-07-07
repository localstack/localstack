import base64
import json
import math
import time
from datetime import datetime

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer, SortingTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.services.lambda_.event_source_mapping.pollers.kinesis_poller import (
    KinesisPoller,
)
from localstack.testing.aws.lambda_utils import (
    _await_event_source_mapping_enabled,
    _await_event_source_mapping_state,
    _get_lambda_invocation_events,
    esm_lambda_permission,
    get_lambda_log_events,
    lambda_role,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import s3_bucket_arn
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import ShortCircuitWaitException, retry, wait_until
from tests.aws.services.lambda_.event_source_mapping.utils import (
    create_lambda_with_response,
)
from tests.aws.services.lambda_.functions import FUNCTIONS_PATH, lambda_integration
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_EVENT_SOURCE_MAPPING_SEND_MESSAGE,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

TEST_LAMBDA_PARALLEL_FILE = FUNCTIONS_PATH / "lambda_parallel.py"
TEST_LAMBDA_KINESIS_LOG = FUNCTIONS_PATH / "kinesis_log.py"
TEST_LAMBDA_KINESIS_BATCH_ITEM_FAILURE = (
    FUNCTIONS_PATH / "lambda_report_batch_item_failures_kinesis.py"
)
TEST_LAMBDA_ECHO_FAILURE = FUNCTIONS_PATH / "lambda_echofail.py"
TEST_LAMBDA_PROVIDED_BOOTSTRAP_EMPTY = FUNCTIONS_PATH / "provided_bootstrap_empty"


@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.key_value("sequenceNumber"))
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformer(
        KeyValueBasedTransformer(
            lambda k, v: str(v) if k == "approximateArrivalTimestamp" else None,
            "<approximate-arrival-timestamp>",
            replace_reference=False,
        )
    )
    snapshot.add_transformer(
        KeyValueBasedTransformer(
            lambda k, v: str(v) if k == "executionStart" else None,
            "<execution-start>",
            replace_reference=False,
        )
    )


@markers.snapshot.skip_snapshot_verify(
    paths=[
        # TODO: Fix transformer conflict between shardId and AWS account number (e.g., 000000000000):
        #  'shardId-000000000000:<sequence-number:1>' → 'shardId-111111111111:<sequence-number:1>' (expected → actual)
        "$..Records..eventID",
        # TODO: Fix transformer issue: 'shardId-000000000000' → 'shardId-111111111111' ... (expected → actual)
        "$..Messages..Body.KinesisBatchInfo.shardId",
        "$..Message.KinesisBatchInfo.shardId",
    ],
)
class TestKinesisSource:
    @markers.aws.validated
    def test_esm_with_not_existing_kinesis_stream(
        self, aws_client, create_lambda_function, lambda_su_role, snapshot, account_id, region_name
    ):
        function_name = f"simple-lambda-{short_uid()}"
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
            timeout=5,
        )
        not_existing_stream_arn = (
            f"arn:aws:kinesis:{region_name}:{account_id}:stream/test-foobar-81ded7e8"
        )
        with pytest.raises(ClientError) as e:
            aws_client.lambda_.create_event_source_mapping(
                EventSourceArn=not_existing_stream_arn,
                FunctionName=function_name,
                StartingPosition="LATEST",
            )
        snapshot.match("error", e.value.response)

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
            runtime=Runtime.python3_12,
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

    @markers.aws.validated
    def test_create_kinesis_event_source_mapping_multiple_lambdas_single_kinesis_event_stream(
        self,
        create_lambda_function,
        kinesis_create_stream,
        lambda_su_role,
        wait_for_stream_ready,
        create_event_source_mapping,
        snapshot,
        aws_client,
    ):
        # create kinesis event stream
        stream_name = f"test-stream-{short_uid()}"
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        # create event source mapping for two lambda functions
        function_a_name = f"lambda_func-{short_uid()}"
        function_b_name = f"lambda_func-{short_uid()}"
        functions = [(function_a_name, "a"), (function_b_name, "b")]
        for function_name, function_id in functions:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=Runtime.python3_12,
                role=lambda_su_role,
            )
            create_event_source_mapping_response = create_event_source_mapping(
                EventSourceArn=stream_arn,
                FunctionName=function_name,
                StartingPosition="TRIM_HORIZON",  # TODO: test with different starting positions
            )
            snapshot.match(
                f"create_event_source_mapping_response-{function_id}",
                create_event_source_mapping_response,
            )

        # send messages to kinesis
        record_data = "hello"
        aws_client.kinesis.put_records(
            Records=[{"Data": record_data, "PartitionKey": "test_1"}],
            StreamName=stream_name,
        )

        # verify that both lambdas are invoked
        for function_name, function_id in functions:
            events = _get_lambda_invocation_events(
                aws_client.logs, function_name, expected_num_events=1, retries=5
            )
            records = events[0]
            snapshot.match(f"kinesis_records-{function_id}", records)
            # check if the timestamp has the correct format
            timestamp = events[0]["Records"][0]["kinesis"]["approximateArrivalTimestamp"]
            # check if the timestamp has same amount of numbers before the comma as the current timestamp
            # this will fail in november 2286, if this code is still around by then, read this comment and update to 10
            assert int(math.log10(timestamp)) == 9

    @markers.aws.validated
    def test_duplicate_event_source_mappings(
        self,
        create_lambda_function,
        lambda_su_role,
        create_event_source_mapping,
        kinesis_create_stream,
        wait_for_stream_ready,
        snapshot,
        aws_client,
    ):
        function_name_1 = f"lambda_func-{short_uid()}"
        function_name_2 = f"lambda_func-{short_uid()}"

        stream_name = f"test-foobar-{short_uid()}"
        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        event_source_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_1,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )

        response = create_event_source_mapping(
            FunctionName=function_name_1,
            EventSourceArn=event_source_arn,
            StartingPosition="LATEST",
        )
        snapshot.match("create", response)

        with pytest.raises(ClientError) as e:
            create_event_source_mapping(
                FunctionName=function_name_1,
                EventSourceArn=event_source_arn,
                StartingPosition="LATEST",
            )

        response = e.value.response
        snapshot.match("error", response)

        # this should work without problem since it's a new function
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_2,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        create_event_source_mapping(
            FunctionName=function_name_2,
            EventSourceArn=event_source_arn,
            StartingPosition="LATEST",
        )

    @markers.aws.validated
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
        """Tests that records are processed in sequence when submitting 2 batches with 10 records each
        because Kinesis streams ensure strict ordering."""
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        num_records_per_batch = 10
        num_batches = 2

        create_lambda_function(
            handler_file=TEST_LAMBDA_PARALLEL_FILE,
            func_name=function_name,
            runtime=Runtime.python3_12,
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

        # Processing of the second batch should happen at least 5 seconds after first batch because the Lambda function
        # of the first batch waits for 5 seconds.
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
            runtime=Runtime.python3_12,
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
            runtime=Runtime.python3_12,
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
            PolicyDefinition=esm_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=function_name,
            runtime=Runtime.python3_12,
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
            assert result.get("Messages")
            return result

        sleep = 15 if is_aws_cloud() else 5
        sqs_payload = retry(verify_failure_received, retries=15, sleep=sleep, sleep_before=5)
        snapshot.match("sqs_payload", sqs_payload)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: Figure out why there is an extra log record
            "$..Records",
        ],
    )
    @markers.aws.validated
    def test_kinesis_report_batch_item_failures(
        self,
        create_lambda_function,
        create_event_source_mapping,
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
            PolicyDefinition=esm_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_KINESIS_BATCH_ITEM_FAILURE,
            func_name=function_name,
            runtime=Runtime.python3_12,
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

        # Use OnFailure config with a DLQ to minimise flakiness instead of relying on Cloudwatch logs
        queue_event_source_mapping = sqs_create_queue()
        destination_queue = sqs_get_queue_arn(queue_event_source_mapping)
        destination_config = {"OnFailure": {"Destination": destination_queue}}

        create_event_source_mapping_response = create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=3,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=kinesis_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=3,
            DestinationConfig=destination_config,
            FunctionResponseTypes=["ReportBatchItemFailures"],
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)

        kinesis_records = [
            {"Data": json.dumps({"should_fail": i == 5}), "PartitionKey": f"test_{i}"}
            for i in range(6)
        ]

        aws_client.kinesis.put_records(
            Records=kinesis_records,
            StreamName=kinesis_name,
        )

        def verify_failure_received():
            result = aws_client.sqs.receive_message(QueueUrl=queue_event_source_mapping)
            assert result.get("Messages")
            return result

        sleep = 15 if is_aws_cloud() else 5
        sqs_payload = retry(verify_failure_received, retries=15, sleep=sleep, sleep_before=5)
        snapshot.match("sqs_payload", sqs_payload)

        batched_records = get_lambda_log_events(function_name, logs_client=aws_client.logs)
        flattened_records = [
            record for batch in batched_records for record in batch.get("Records", [])
        ]
        sorted_records = sorted(flattened_records, key=lambda item: item["kinesis"]["partitionKey"])

        snapshot.match("kinesis_records", {"Records": sorted_records})

    @markers.aws.validated
    @pytest.mark.parametrize(
        "set_lambda_response",
        [
            # Failures
            {"batchItemFailures": [{"itemIdentifier": 123}]},
            {"batchItemFailures": [{"itemIdentifier": ""}]},
            {"batchItemFailures": [{"itemIdentifier": None}]},
            {"batchItemFailures": [{"foo": 123}]},
            {"batchItemFailures": [{"foo": None}]},
            # Unhandled Exceptions
            "(lambda: 1 / 0)()",  # This will (lazily) evaluate, raise an exception, and re-trigger the whole batch
        ],
        ids=[
            # Failures
            "item_identifier_not_present_failure",
            "empty_string_item_identifier_failure",
            "null_item_identifier_failure",
            "invalid_key_foo_failure",
            "invalid_key_foo_null_value_failure",
            # Unhandled Exceptions
            "unhandled_exception_in_function",
        ],
    )
    def test_kinesis_report_batch_item_failure_scenarios(
        self,
        create_lambda_function,
        create_event_source_mapping,
        kinesis_create_stream,
        lambda_su_role,
        wait_for_stream_ready,
        snapshot,
        aws_client,
        set_lambda_response,
        sqs_get_queue_arn,
        sqs_create_queue,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))

        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        record_data = "hello"

        create_lambda_function(
            handler_file=create_lambda_with_response(set_lambda_response),
            func_name=function_name,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        queue_event_source_mapping = sqs_create_queue()
        destination_queue = sqs_get_queue_arn(queue_event_source_mapping)
        destination_config = {"OnFailure": {"Destination": destination_queue}}

        create_event_source_mapping_response = create_event_source_mapping(
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
            BatchSize=1,
            MaximumBatchingWindowInSeconds=1,
            FunctionResponseTypes=["ReportBatchItemFailures"],
            MaximumRetryAttempts=2,
            DestinationConfig=destination_config,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        aws_client.kinesis.put_record(
            Data=record_data,
            PartitionKey="test",
            StreamName=stream_name,
        )

        def verify_failure_received():
            result = aws_client.sqs.receive_message(QueueUrl=queue_event_source_mapping)
            assert result.get("Messages")
            return result

        sleep = 15 if is_aws_cloud() else 5
        sqs_payload = retry(verify_failure_received, retries=15, sleep=sleep, sleep_before=5)
        snapshot.match("sqs_payload", sqs_payload)

        events = get_lambda_log_events(function_name, logs_client=aws_client.logs)

        # This will filter out exception messages being added to the log stream
        invocation_events = [event for event in events if "Records" in event]
        snapshot.match("kinesis_events", invocation_events)

    @markers.aws.validated
    def test_kinesis_event_source_mapping_with_sns_on_failure_destination_config(
        self,
        create_lambda_function,
        sqs_get_queue_arn,
        sqs_create_queue,
        sns_create_topic,
        sns_allow_topic_sqs_queue,
        create_iam_role_with_policy,
        wait_for_stream_ready,
        cleanups,
        snapshot,
        aws_client,
    ):
        # snapshot setup
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))

        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        kinesis_name = f"test-kinesis-{short_uid()}"
        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=esm_lambda_permission,
        )

        # create topic and queue
        queue_url = sqs_create_queue()
        topic_info = sns_create_topic()
        topic_arn = topic_info["TopicArn"]

        # subscribe SQS to SNS
        queue_arn = sqs_get_queue_arn(queue_url)
        subscription = aws_client.sns.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
        )
        cleanups.append(
            lambda: aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        )

        sns_allow_topic_sqs_queue(
            sqs_queue_url=queue_url, sqs_queue_arn=queue_arn, sns_topic_arn=topic_arn
        )
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=function_name,
            runtime=Runtime.python3_12,
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

        destination_config = {"OnFailure": {"Destination": topic_arn}}
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
            result = aws_client.sqs.receive_message(QueueUrl=queue_url)
            assert result["Messages"]
            return result

        messages = retry(verify_failure_received, retries=50, sleep=5, sleep_before=5)

        # The failure context payload of the SQS response is in JSON-string format.
        # Rather extract, parse, and snapshot it since the SQS information is irrelevant.
        failure_sns_payload = messages.get("Messages", []).pop(0)
        failure_sns_body_json = failure_sns_payload.get("Body", {})
        failure_sns_message = json.loads(failure_sns_body_json)

        snapshot.match("failure_sns_message", failure_sns_message)

    @markers.aws.validated
    def test_kinesis_event_source_mapping_with_s3_on_failure_destination(
        self,
        s3_bucket,
        create_lambda_function,
        aws_client,
        cleanups,
        wait_for_stream_ready,
        create_iam_role_with_policy,
        region_name,
        snapshot,
    ):
        # set up s3, lambda, kinesis

        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        kinesis_name = f"test-kinesis-{short_uid()}"

        bucket_name = s3_bucket
        bucket_arn = s3_bucket_arn(bucket_name, region=region_name)

        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=esm_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON,
            func_name=function_name,
            runtime=Runtime.python3_12,
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

        # create event source mapping

        destination_config = {"OnFailure": {"Destination": bucket_arn}}
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

        # trigger ESM source

        aws_client.kinesis.put_record(
            StreamName=kinesis_name, Data=to_bytes(json.dumps(message)), PartitionKey="custom"
        )

        # add snapshot transformers

        snapshot.add_transformer(snapshot.transform.key_value("ETag"))
        snapshot.add_transformer(snapshot.transform.regex(r"shardId-\d+", "<kinesis-shard-id>"))

        # verify failure record data

        def get_invocation_record():
            list_objects_response = aws_client.s3.list_objects_v2(Bucket=bucket_name)
            bucket_objects = list_objects_response["Contents"]
            assert len(bucket_objects) == 1
            object_key = bucket_objects[0]["Key"]

            invocation_record = aws_client.s3.get_object(
                Bucket=bucket_name,
                Key=object_key,
            )
            return invocation_record, object_key

        sleep = 15 if is_aws_cloud() else 5
        s3_invocation_record, s3_object_key = retry(
            get_invocation_record, retries=15, sleep=sleep, sleep_before=5
        )

        record_body = json.loads(s3_invocation_record["Body"].read().decode("utf-8"))
        snapshot.match("record_body", record_body)

        failure_datetime = datetime.fromisoformat(record_body["timestamp"])
        timestamp = failure_datetime.strftime("%Y-%m-%dT%H.%M.%S")
        year_month_day = failure_datetime.strftime("%Y/%m/%d")
        assert s3_object_key.startswith(
            f"aws/lambda/{event_source_mapping_uuid}/{record_body['KinesisBatchInfo']['shardId']}/{year_month_day}/{timestamp}"
        )  # there is a random UUID at the end of object key, checking that the key starts with deterministic values

    @markers.aws.validated
    @pytest.mark.parametrize(
        "set_lambda_response",
        [
            # Successes
            "",
            [],
            None,
            {},
            {"batchItemFailures": []},
            {"batchItemFailures": None},
        ],
        ids=[
            # Successes
            "empty_string_success",
            "empty_list_success",
            "null_success",
            "empty_dict_success",
            "empty_batch_item_failure_success",
            "null_batch_item_failure_success",
        ],
    )
    def test_kinesis_report_batch_item_success_scenarios(
        self,
        create_lambda_function,
        kinesis_create_stream,
        lambda_su_role,
        wait_for_stream_ready,
        cleanups,
        snapshot,
        aws_client,
        set_lambda_response,
    ):
        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-foobar-{short_uid()}"
        record_data = "hello"

        create_lambda_function(
            handler_file=create_lambda_with_response(set_lambda_response),
            func_name=function_name,
            runtime=Runtime.python3_12,
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
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
            BatchSize=1,
            MaximumBatchingWindowInSeconds=1,
            FunctionResponseTypes=["ReportBatchItemFailures"],
            MaximumRetryAttempts=2,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        aws_client.kinesis.put_record(
            Data=record_data,
            PartitionKey="test",
            StreamName=stream_name,
        )

        def _verify_messages_received():
            events = get_lambda_log_events(function_name, logs_client=aws_client.logs)

            # This will filter out exception messages being added to the log stream
            record_events = [event for event in events if "Records" in event]

            assert len(record_events) >= 1
            return record_events

        invocation_events = retry(_verify_messages_received, retries=30, sleep=5)
        snapshot.match("kinesis_events", invocation_events)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # FIXME: Generate and send a requestContext in StreamPoller for RecordAgeExceeded
            # which contains no responseContext object.
            "$..Messages..Body.requestContext",
            "$..Messages..MessageId",  # Skip while no requestContext generated in StreamPoller due to transformation issues
        ]
    )
    @pytest.mark.parametrize(
        "processing_delay_seconds, max_retries",
        [
            # The record expired while retrying
            pytest.param(0, -1, id="expire-while-retrying"),
            # The record expired prior to arriving (no retries expected)
            pytest.param(60 if is_aws_cloud() else 5, 0, id="expire-before-ingestion"),
        ],
    )
    @pytest.mark.requires_in_process
    def test_kinesis_maximum_record_age_exceeded(
        self,
        create_lambda_function,
        kinesis_create_stream,
        sqs_get_queue_arn,
        create_event_source_mapping,
        lambda_su_role,
        wait_for_stream_ready,
        snapshot,
        aws_client,
        sqs_create_queue,
        monkeypatch,
        # Parametrized arguments
        processing_delay_seconds,
        max_retries,
    ):
        # snapshot setup
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))

        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-kinesis-{short_uid()}"

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        if not is_aws_cloud():
            # LocalStack test optimization: Override MaximumRecordAgeInSeconds directly
            # in the poller to bypass the AWS API validation (where MaximumRecordAgeInSeconds >= 60s).
            # This saves 55s waiting time.
            def _patched_stream_parameters(self):
                params = self.source_parameters.get("KinesisStreamParameters", {})
                params["MaximumRecordAgeInSeconds"] = 5
                return params

            monkeypatch.setattr(
                KinesisPoller, "stream_parameters", property(_patched_stream_parameters)
            )

        aws_client.kinesis.put_record(
            Data="stream-data",
            PartitionKey="test",
            StreamName=stream_name,
        )

        # Optionally delay the ESM creation, allowing a record to expire prior to being ingested.
        time.sleep(processing_delay_seconds)

        create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FAILURE,
            func_name=function_name,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )

        # Use OnFailure config with a DLQ to minimise flakiness instead of relying on Cloudwatch logs
        queue_event_source_mapping = sqs_create_queue()
        destination_queue = sqs_get_queue_arn(queue_event_source_mapping)
        destination_config = {"OnFailure": {"Destination": destination_queue}}

        create_event_source_mapping_response = create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=max_retries,
            MaximumRecordAgeInSeconds=60,
            DestinationConfig=destination_config,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)

        def _verify_failure_received():
            result = aws_client.sqs.receive_message(QueueUrl=queue_event_source_mapping)
            assert result.get("Messages")
            return result

        sleep = 15 if is_aws_cloud() else 5
        record_age_exceeded_payload = retry(
            _verify_failure_received, retries=30, sleep=sleep, sleep_before=5
        )
        snapshot.match("record_age_exceeded_payload", record_age_exceeded_payload)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # FIXME: Generate and send a requestContext in StreamPoller for RecordAgeExceeded
            # which contains no responseContext object.
            "$..Messages..Body.requestContext",
            "$..Messages..MessageId",  # Skip while no requestContext generated in StreamPoller due to transformation issues
        ]
    )
    @pytest.mark.requires_in_process
    def test_kinesis_maximum_record_age_exceeded_discard_records(
        self,
        create_lambda_function,
        kinesis_create_stream,
        sqs_get_queue_arn,
        create_event_source_mapping,
        lambda_su_role,
        wait_for_stream_ready,
        snapshot,
        aws_client,
        sqs_create_queue,
        monkeypatch,
    ):
        # snapshot setup
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))

        # PutRecords does not have guaranteed ordering so we should sort the retrieved records to ensure consistency
        # between runs.
        snapshot.add_transformer(
            SortingTransformer(
                "Records", lambda x: base64.b64decode(x["kinesis"]["data"]).decode("utf-8")
            ),
        )

        function_name = f"lambda_func-{short_uid()}"
        stream_name = f"test-kinesis-{short_uid()}"
        wait_before_processing = 80

        if not is_aws_cloud():
            wait_before_processing = 5

            # LS test optimization
            def _patched_stream_parameters(self):
                params = self.source_parameters.get("KinesisStreamParameters", {})
                params["MaximumRecordAgeInSeconds"] = wait_before_processing
                return params

            monkeypatch.setattr(
                KinesisPoller, "stream_parameters", property(_patched_stream_parameters)
            )

        kinesis_create_stream(StreamName=stream_name, ShardCount=1)
        wait_for_stream_ready(stream_name=stream_name)
        stream_summary = aws_client.kinesis.describe_stream_summary(StreamName=stream_name)
        assert stream_summary["StreamDescriptionSummary"]["OpenShardCount"] == 1
        stream_arn = aws_client.kinesis.describe_stream(StreamName=stream_name)[
            "StreamDescription"
        ]["StreamARN"]

        aws_client.kinesis.put_record(
            Data="stream-data",
            PartitionKey="test",
            StreamName=stream_name,
        )

        # Ensure that the first record has expired
        time.sleep(wait_before_processing)

        # The first record in the batch will have expired with the remaining batch not exceeding any age-limits.
        aws_client.kinesis.put_records(
            Records=[{"Data": f"stream-data-{i + 1}", "PartitionKey": "test"} for i in range(5)],
            StreamName=stream_name,
        )

        destination_queue_url = sqs_create_queue()
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_EVENT_SOURCE_MAPPING_SEND_MESSAGE,
            runtime=Runtime.python3_12,
            envvars={"SQS_QUEUE_URL": destination_queue_url},
            role=lambda_su_role,
        )

        # Use OnFailure config with a DLQ to minimise flakiness instead of relying on Cloudwatch logs
        dead_letter_queue = sqs_create_queue()
        dead_letter_queue_arn = sqs_get_queue_arn(dead_letter_queue)
        destination_config = {"OnFailure": {"Destination": dead_letter_queue_arn}}

        create_event_source_mapping_response = create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=10,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=0,
            MaximumRecordAgeInSeconds=60,
            DestinationConfig=destination_config,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)

        def _verify_failure_received():
            result = aws_client.sqs.receive_message(QueueUrl=dead_letter_queue)
            assert result.get("Messages")
            return result

        batches = []

        def _verify_events_received(expected: int):
            messages_to_delete = []
            receive_message_response = aws_client.sqs.receive_message(
                QueueUrl=destination_queue_url,
                MaxNumberOfMessages=10,
                VisibilityTimeout=120,
                WaitTimeSeconds=5 if is_aws_cloud() else 1,
            )
            messages = receive_message_response.get("Messages", [])
            for message in messages:
                received_batch = json.loads(message["Body"])
                batches.append(received_batch)
                messages_to_delete.append(
                    {"Id": message["MessageId"], "ReceiptHandle": message["ReceiptHandle"]}
                )
            if messages_to_delete:
                aws_client.sqs.delete_message_batch(
                    QueueUrl=destination_queue_url, Entries=messages_to_delete
                )
            assert sum([len(batch) for batch in batches]) == expected
            return [message for batch in batches for message in batch]

        sleep = 15 if is_aws_cloud() else 5
        record_age_exceeded_payload = retry(
            _verify_failure_received, retries=15, sleep=sleep, sleep_before=5
        )
        snapshot.match("record_age_exceeded_payload", record_age_exceeded_payload)

        # While 6 records were sent, we expect 5 records since the first
        # record should have expired and been discarded.
        kinesis_events = retry(
            _verify_events_received, retries=30, sleep=sleep, sleep_before=5, expected=5
        )
        snapshot.match("Records", kinesis_events)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO: Fix flaky status 'OK' → 'No records processed' ... (expected → actual)
            "$..LastProcessingResult",
        ],
    )
    def test_kinesis_empty_provided(
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

        create_lambda_function(
            handler_file=TEST_LAMBDA_PROVIDED_BOOTSTRAP_EMPTY,
            func_name=function_name,
            runtime=Runtime.provided_al2023,
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
            EventSourceArn=stream_arn,
            FunctionName=function_name,
            StartingPosition="TRIM_HORIZON",
            BatchSize=1,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=2,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        aws_client.kinesis.put_record(
            Data=record_data,
            PartitionKey="test",
            StreamName=stream_name,
        )

        def _verify_invoke():
            log_events = aws_client.logs.filter_log_events(
                logGroupName=f"/aws/lambda/{function_name}",
            )["events"]
            assert len([e["message"] for e in log_events if e["message"].startswith("REPORT")]) == 1

        retry(_verify_invoke, retries=30, sleep=5)

        get_esm_result = aws_client.lambda_.get_event_source_mapping(UUID=uuid)
        snapshot.match("get_esm_result", get_esm_result)


# TODO: add tests for different edge cases in filtering (e.g. message isn't json => needs to be dropped)
# https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-kinesis
class TestKinesisEventFiltering:
    @markers.aws.validated
    def test_kinesis_event_filtering_json_pattern(
        self,
        create_lambda_function,
        create_iam_role_with_policy,
        wait_for_stream_ready,
        cleanups,
        snapshot,
        aws_client,
    ):
        """
        1 kinesis stream + 2 lambda functions
        each function has a different event source mapping with a different filter on the same kinesis stream
        """
        # snapshot setup
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))

        function1_name = f"lambda_func1-{short_uid()}"
        function2_name = f"lambda_func2-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        kinesis_name = f"test-kinesis-{short_uid()}"
        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=esm_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_KINESIS_LOG,
            func_name=function1_name,
            runtime=Runtime.python3_12,
            role=role_arn,
        )
        create_lambda_function(
            handler_file=TEST_LAMBDA_KINESIS_LOG,
            func_name=function2_name,
            runtime=Runtime.python3_12,
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

        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function1_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=kinesis_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
            FilterCriteria={
                "Filters": [{"Pattern": json.dumps({"data": {"event_type": ["function_1"]}})}]
            },
        )

        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)

        create_event_source_mapping_2_response = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function2_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=kinesis_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
            FilterCriteria={
                "Filters": [{"Pattern": json.dumps({"data": {"event_type": ["function_2"]}})}]
            },
        )
        snapshot.match(
            "create_event_source_mapping_2_response", create_event_source_mapping_2_response
        )
        event_source_mapping_2_uuid = create_event_source_mapping_2_response["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_mapping_2_uuid)
        )
        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_2_uuid)

        msg1 = {"event_type": "function_1", "message": "foo"}
        msg2 = {"event_type": "function_2", "message": "bar"}
        aws_client.kinesis.put_record(
            StreamName=kinesis_name, Data=to_bytes(json.dumps(msg1)), PartitionKey="custom"
        )
        aws_client.kinesis.put_record(
            StreamName=kinesis_name, Data=to_bytes(json.dumps(msg2)), PartitionKey="custom"
        )

        # on AWS this can take a bit (~2 min)

        def _wait_lambda_fn_invoked_x_times(fn_name: str, x: int):
            def _inner():
                log_events = aws_client.logs.filter_log_events(
                    logGroupName=f"/aws/lambda/{fn_name}"
                )
                report_events = [e for e in log_events["events"] if "REPORT" in e["message"]]
                report_count = len(report_events)
                if report_count > x:
                    raise ShortCircuitWaitException(
                        f"Too many events. Expected {x}, received {len(report_events)}"
                    )
                elif report_count == x:
                    return True
                else:
                    return False

            return _inner

        assert wait_until(_wait_lambda_fn_invoked_x_times(function1_name, 1))
        log_events = aws_client.logs.filter_log_events(logGroupName=f"/aws/lambda/{function1_name}")
        records = [e for e in log_events["events"] if "{" in e["message"]]
        message = records[0]["message"]
        # TODO: missing trailing \n is a LocalStack Lambda logging issue
        snapshot.match("kinesis-record-lambda-payload", message.strip())
        assert wait_until(_wait_lambda_fn_invoked_x_times(function2_name, 1))
