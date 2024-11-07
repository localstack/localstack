import json
import math
import time

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.aws.lambda_utils import (
    _await_event_source_mapping_enabled,
    _await_event_source_mapping_state,
    _get_lambda_invocation_events,
    get_lambda_log_events,
    lambda_role,
    s3_lambda_permission,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import ShortCircuitWaitException, retry, wait_until
from tests.aws.services.lambda_.event_source_mapping.utils import (
    create_lambda_with_response,
)
from tests.aws.services.lambda_.functions import FUNCTIONS_PATH, lambda_integration
from tests.aws.services.lambda_.test_lambda import (
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

TEST_LAMBDA_PARALLEL_FILE = FUNCTIONS_PATH / "lambda_parallel.py"
TEST_LAMBDA_KINESIS_LOG = FUNCTIONS_PATH / "kinesis_log.py"
TEST_LAMBDA_KINESIS_BATCH_ITEM_FAILURE = (
    FUNCTIONS_PATH / "lambda_report_batch_item_failures_kinesis.py"
)
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
        "$..Records..eventID",
        "$..BisectBatchOnFunctionError",
        "$..DestinationConfig",
        "$..LastProcessingResult",
        "$..EventSourceMappingArn",
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

    # TODO: is this test relevant for the new provider without patching SYNCHRONOUS_KINESIS_EVENTS?
    #   At least, it is flagged as AWS-validated.
    @markers.aws.validated
    @pytest.mark.skip(reason="deprecated config that only worked using the legacy provider")
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

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.KinesisBatchInfo.shardId",
            "$..Messages..Body.KinesisBatchInfo.streamArn",
        ],
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
            # FIXME Conflict between shardId and AWS account number when transforming
            # i.e "shardId-000000000000" versus AWS Account ID 000000000000
            "$..Messages..Body.KinesisBatchInfo.shardId",
            "$..Messages..Body.KinesisBatchInfo.streamArn",
            "$..Records",  # FIXME Figure out why there is an extra log record
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
            PolicyDefinition=s3_lambda_permission,
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.KinesisBatchInfo.shardId",
        ],
    )
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

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Message.KinesisBatchInfo.shardId",
            "$..Message.KinesisBatchInfo.streamArn",
        ],
    )
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
            PolicyDefinition=s3_lambda_permission,
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.KinesisBatchInfo.shardId",
        ],
    )
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
            "$..Messages..Body.KinesisBatchInfo.shardId",
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
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Lifecycle updates not yet implemented in ESM v2
            "$..LastProcessingResult",
        ],
    )
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.KinesisBatchInfo.shardId",
            "$..Messages..Body.KinesisBatchInfo.streamArn",
            "$..EventSourceMappingArn",
        ],
    )
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
            PolicyDefinition=s3_lambda_permission,
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
