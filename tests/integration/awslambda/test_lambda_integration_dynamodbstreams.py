import json
import math
import time

import pytest

from localstack.services.awslambda.lambda_api import INVALID_PARAMETER_VALUE_EXCEPTION
from localstack.services.awslambda.lambda_utils import (
    LAMBDA_RUNTIME_PYTHON37,
    LAMBDA_RUNTIME_PYTHON39,
)
from localstack.testing.aws.lambda_utils import (
    _await_dynamodb_table_active,
    _await_event_source_mapping_enabled,
    _get_lambda_invocation_events,
    is_old_provider,
    lambda_role,
    s3_lambda_permission,
)
from localstack.testing.snapshots.transformer import KeyValueBasedTransformer
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events
from tests.integration.awslambda.test_lambda import (
    TEST_LAMBDA_PYTHON_ECHO,
    TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
)


@pytest.fixture(autouse=True)
def _snapshot_transformers(snapshot):
    # manual transformers since we are passing SQS attributes through lambdas and back again
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformer(
        KeyValueBasedTransformer(
            lambda k, v: str(v) if k == "ApproximateCreationDateTime" else None,
            "<approximate-creation-datetime>",
            replace_reference=False,
        )
    )
    snapshot.add_transformer(snapshot.transform.key_value("SequenceNumber"))
    snapshot.add_transformer(snapshot.transform.key_value("eventID"))
    snapshot.add_transformer(snapshot.transform.key_value("shardId"))


@pytest.fixture
def wait_for_dynamodb_stream_enabled(dynamodbstreams_client):
    def _wait_for_stream_enabled(latest_stream_arn: str):
        def _is_stream_enabled():
            return (
                dynamodbstreams_client.describe_stream(StreamArn=latest_stream_arn)[
                    "StreamDescription"
                ]["StreamStatus"]
                == "ENABLED"
            )

        return poll_condition(_is_stream_enabled, timeout=30)

    return _wait_for_stream_enabled


@pytest.fixture
def get_lambda_logs_event(logs_client):
    def _get_lambda_logs_event(function_name, expected_num_events, retries=30):
        return _get_lambda_invocation_events(
            logs_client=logs_client,
            function_name=function_name,
            expected_num_events=expected_num_events,
            retries=retries,
        )

    return _get_lambda_logs_event


@pytest.mark.skip_snapshot_verify(
    condition=is_old_provider,
    paths=[
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
@pytest.mark.skip_snapshot_verify(
    paths=[
        # dynamodb issues, not related to lambda
        "$..TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime",
        "$..TableDescription.ProvisionedThroughput.LastDecreaseDateTime",
        "$..TableDescription.ProvisionedThroughput.LastIncreaseDateTime",
        "$..TableDescription.StreamSpecification",
        "$..TableDescription.TableStatus",
        "$..Records..dynamodb.SizeBytes",
        "$..Records..eventVersion",
    ],
)
class TestDynamoDBEventSourceMapping:
    @pytest.mark.aws_validated
    def test_dynamodb_event_source_mapping(
        self,
        lambda_client,
        create_lambda_function,
        create_iam_role_with_policy,
        dynamodb_client,
        dynamodb_create_table,
        get_lambda_logs_event,
        cleanups,
        wait_for_dynamodb_stream_enabled,
        snapshot,
    ):

        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"
        db_item = {partition_key: {"S": "hello world"}}
        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=s3_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=role_arn,
        )
        create_table_result = dynamodb_create_table(
            table_name=table_name, partition_key=partition_key
        )
        # snapshot create table to get the table name registered as resource
        snapshot.match("create-table-result", create_table_result)
        _await_dynamodb_table_active(dynamodb_client, table_name)
        stream_arn = dynamodb_client.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )["TableDescription"]["LatestStreamArn"]
        assert wait_for_dynamodb_stream_enabled(stream_arn)
        create_event_source_mapping_response = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",  # TODO investigate how to get it back to LATEST
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=event_source_uuid))

        _await_event_source_mapping_enabled(lambda_client, event_source_uuid)

        def _send_and_receive_events():
            dynamodb_client.put_item(TableName=table_name, Item=db_item)
            return get_lambda_logs_event(
                function_name=function_name, expected_num_events=1, retries=20
            )

        event_logs = retry(_send_and_receive_events, retries=3)
        snapshot.match("event_logs", event_logs)
        # check if the timestamp has the correct format
        timestamp = event_logs[0]["Records"][0]["dynamodb"]["ApproximateCreationDateTime"]
        # check if the timestamp has same amount of numbers before the comma as the current timestamp
        # this will fail in november 2286, if this code is still around by then, read this comment and update to 10
        assert int(math.log10(timestamp)) == 9

    @pytest.mark.aws_validated
    def test_disabled_dynamodb_event_source_mapping(
        self,
        create_lambda_function,
        lambda_client,
        dynamodb_resource,
        dynamodb_create_table,
        logs_client,
        dynamodbstreams_client,
        lambda_su_role,
        cleanups,
        wait_for_dynamodb_stream_enabled,
        snapshot,
    ):

        function_name = f"lambda_func-{short_uid()}"
        ddb_table = f"ddb_table-{short_uid()}"
        items = [
            {"id": short_uid(), "data": "data1"},
            {"id": short_uid(), "data": "data2"},
        ]
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            role=lambda_su_role,
        )
        dynamodb_create_table_result = dynamodb_create_table(
            table_name=ddb_table, partition_key="id", stream_view_type="NEW_IMAGE"
        )
        latest_stream_arn = dynamodb_create_table_result["TableDescription"]["LatestStreamArn"]
        snapshot.match("dynamodb_create_table_result", dynamodb_create_table_result)
        rs = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=latest_stream_arn,
            StartingPosition="TRIM_HORIZON",
            MaximumBatchingWindowInSeconds=1,
        )
        snapshot.match("create_event_source_mapping_result", rs)
        uuid = rs["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(lambda_client, uuid)

        assert wait_for_dynamodb_stream_enabled(latest_stream_arn)
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
        update_event_source_mapping_result = lambda_client.update_event_source_mapping(
            UUID=uuid, Enabled=False
        )
        snapshot.match("update_event_source_mapping_result", update_event_source_mapping_result)
        time.sleep(2)
        table.put_item(Item=items[1])
        # lambda no longer invoked, still have 1 event
        check_expected_lambda_log_events_length(
            expected_length=1, function_name=function_name, logs_client=logs_client
        )

    @pytest.mark.aws_validated
    def test_deletion_event_source_mapping_with_dynamodb(
        self,
        create_lambda_function,
        lambda_client,
        dynamodb_client,
        lambda_su_role,
        snapshot,
        cleanups,
        dynamodb_create_table,
    ):
        function_name = f"lambda_func-{short_uid()}"
        ddb_table = f"ddb_table-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=lambda_su_role,
        )
        create_dynamodb_table_response = dynamodb_create_table(
            table_name=ddb_table,
            partition_key="id",
            client=dynamodb_client,
            stream_view_type="NEW_IMAGE",
        )
        snapshot.match("create_dynamodb_table_response", create_dynamodb_table_response)
        _await_dynamodb_table_active(dynamodb_client, ddb_table)
        latest_stream_arn = create_dynamodb_table_response["TableDescription"]["LatestStreamArn"]
        result = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=latest_stream_arn,
            StartingPosition="TRIM_HORIZON",
        )
        snapshot.match("create_event_source_mapping_result", result)
        _await_event_source_mapping_enabled(lambda_client, result["UUID"])
        cleanups.append(lambda: dynamodb_client.delete_table(TableName=ddb_table))

        event_source_mapping_uuid = result["UUID"]
        cleanups.append(
            lambda: lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )
        dynamodb_client.delete_table(TableName=ddb_table)
        list_esm = lambda_client.list_event_source_mappings(EventSourceArn=latest_stream_arn)
        snapshot.match("list_event_source_mapping_result", list_esm)

    @pytest.mark.aws_validated
    # FIXME last three skip verification entries are purely due to numbering mismatches
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.requestContext.approximateInvokeCount",
            "$..Messages..Body.requestContext.functionArn",
            "$..Messages..Body.requestContext.requestId",
            "$..Messages..Body.responseContext.statusCode",
            "$..Messages..MessageId",
            "$..TableDescription.TableId",
            "$..FunctionArn",
            "$..UUID",
        ],
    )
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
        snapshot,
        cleanups,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
        snapshot.add_transformer(snapshot.transform.key_value("ReceiptHandle"))
        snapshot.add_transformer(snapshot.transform.key_value("startSequenceNumber"))
        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"
        item = {partition_key: {"S": "hello world"}}

        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=s3_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_UNHANDLED_ERROR,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON39,
            role=role_arn,
        )
        dynamodb_create_table(table_name=table_name, partition_key=partition_key)
        _await_dynamodb_table_active(dynamodb_client, table_name)
        update_table_response = dynamodb_client.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )
        snapshot.match("update_table_response", update_table_response)
        stream_arn = update_table_response["TableDescription"]["LatestStreamArn"]
        destination_queue = sqs_create_queue()
        queue_failure_event_source_mapping_arn = sqs_queue_arn(destination_queue)
        destination_config = {"OnFailure": {"Destination": queue_failure_event_source_mapping_arn}}
        create_event_source_mapping_response = lambda_client.create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
            DestinationConfig=destination_config,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_mapping_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(
            lambda: lambda_client.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )

        _await_event_source_mapping_enabled(lambda_client, event_source_mapping_uuid)

        dynamodb_client.put_item(TableName=table_name, Item=item)

        def verify_failure_received():
            res = sqs_client.receive_message(QueueUrl=destination_queue)
            assert res.get("Messages")
            return res

        messages = retry(verify_failure_received, retries=15, sleep=5, sleep_before=5)
        snapshot.match("destination_queue_messages", messages)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "item_to_put1, item_to_put2, filter, calls",
        [
            # Test with filter, and two times same entry
            (
                {"id": {"S": "test123"}, "id2": {"S": "test42"}},
                None,
                {"eventName": ["INSERT"]},
                1,
            ),
            # Test with OR filter
            (
                {"id": {"S": "test123"}},
                {"id": {"S": "test123"}, "id2": {"S": "42test"}},
                {"eventName": ["INSERT", "MODIFY"]},
                2,
            ),
            # Test with 2 filters (AND), and two times same entry (second time modified aka MODIFY eventName)
            (
                {"id": {"S": "test123"}},
                {"id": {"S": "test123"}, "id2": {"S": "42test"}},
                {"eventName": ["INSERT"], "eventSource": ["aws:dynamodb"]},
                1,
            ),
            # Test exists filter
            (
                {"id": {"S": "test123"}},
                {"id": {"S": "test1234"}, "presentKey": {"S": "test123"}},
                {"dynamodb": {"NewImage": {"presentKey": [{"exists": False}]}}},
                1,
            ),
            # numeric filters
            # NOTE: numeric filters seem not to work with DynamoDB as the values are represented as string
            # and it looks like that there is no conversion happening
            # I leave the test here in case this changes in future.
            (
                {"id": {"S": "test123"}, "numericFilter": {"N": "123"}},
                {"id": {"S": "test1234"}, "numericFilter": {"N": "12"}},
                {"dynamodb": {"NewImage": {"numericFilter": {"N": [{"numeric": [">", 100]}]}}}},
                0,
            ),
            (
                {"id": {"S": "test123"}, "numericFilter": {"N": "100"}},
                {"id": {"S": "test1234"}, "numericFilter": {"N": "12"}},
                {
                    "dynamodb": {
                        "NewImage": {"numericFilter": {"N": [{"numeric": [">=", 100, "<", 200]}]}}
                    }
                },
                0,
            ),
            # Prefix
            (
                {"id": {"S": "test123"}, "prefix": {"S": "us-1-testtest"}},
                {"id": {"S": "test1234"}, "prefix": {"S": "testtest"}},
                {"dynamodb": {"NewImage": {"prefix": {"S": [{"prefix": "us-1"}]}}}},
                1,
            ),
        ],
    )
    def test_dynamodb_event_filter(
        self,
        create_lambda_function,
        lambda_client,
        dynamodb_client,
        dynamodb_create_table,
        lambda_su_role,
        logs_client,
        wait_for_dynamodb_stream_ready,
        filter,
        calls,
        item_to_put1,
        item_to_put2,
        cleanups,
        snapshot,
    ):

        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        max_retries = 50

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            role=lambda_su_role,
        )
        table_creation_response = dynamodb_create_table(table_name=table_name, partition_key="id")
        snapshot.match("table_creation_response", table_creation_response)
        _await_dynamodb_table_active(dynamodb_client, table_name)
        stream_arn = dynamodb_client.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )["TableDescription"]["LatestStreamArn"]
        wait_for_dynamodb_stream_ready(stream_arn)
        event_source_mapping_kwargs = {
            "FunctionName": function_name,
            "BatchSize": 1,
            "StartingPosition": "TRIM_HORIZON",
            "EventSourceArn": stream_arn,
            "MaximumBatchingWindowInSeconds": 1,
            "MaximumRetryAttempts": 1,
        }
        event_source_mapping_kwargs.update(
            FilterCriteria={
                "Filters": [
                    {"Pattern": json.dumps(filter)},
                ]
            }
        )

        create_event_source_mapping_response = lambda_client.create_event_source_mapping(
            **event_source_mapping_kwargs
        )
        event_source_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(lambda: lambda_client.delete_event_source_mapping(UUID=event_source_uuid))
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)

        _await_event_source_mapping_enabled(lambda_client, event_source_uuid)
        dynamodb_client.put_item(TableName=table_name, Item=item_to_put1)

        def assert_lambda_called():
            events = get_lambda_log_events(function_name, logs_client=logs_client)
            if calls > 0:
                assert len(events) == 1
            else:
                # negative test for 'numeric' filter
                assert len(events) == 0
            return events

        events = retry(assert_lambda_called, retries=max_retries)
        snapshot.match("lambda-log-events", events)

        # Following lines are relevant if variables are set via parametrize
        if item_to_put2:
            # putting a new item (item_to_put2) a second time is a 'INSERT' request
            dynamodb_client.put_item(TableName=table_name, Item=item_to_put2)
        else:
            # putting the same item (item_to_put1) a second time is a 'MODIFY' request (at least in Localstack)
            dynamodb_client.put_item(TableName=table_name, Item=item_to_put1)
        # depending on the parametrize values the filter (and the items to put) the lambda might be called multiple times
        if calls > 1:

            def assert_events_called_multiple():
                events = get_lambda_log_events(function_name, logs_client=logs_client)
                assert len(events) == calls
                return events

            # lambda was called a second time, so new records should be found
            events = retry(assert_events_called_multiple, retries=max_retries)
        else:
            # lambda wasn't called a second time, so no new records should be found
            events = retry(assert_lambda_called, retries=max_retries)
        snapshot.match("lambda-multiple-log-events", events)

    @pytest.mark.aws_validated
    @pytest.mark.parametrize(
        "filter",
        [
            "single-string",
            '[{"eventName": ["INSERT"=123}]',
        ],
    )
    def test_dynamodb_invalid_event_filter(
        self,
        create_lambda_function,
        lambda_client,
        dynamodb_client,
        dynamodb_create_table,
        lambda_su_role,
        wait_for_dynamodb_stream_ready,
        filter,
        snapshot,
    ):

        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            role=lambda_su_role,
        )
        dynamodb_create_table(table_name=table_name, partition_key="id")
        _await_dynamodb_table_active(dynamodb_client, table_name)
        stream_arn = dynamodb_client.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_AND_OLD_IMAGES"},
        )["TableDescription"]["LatestStreamArn"]
        wait_for_dynamodb_stream_ready(stream_arn)
        event_source_mapping_kwargs = {
            "FunctionName": function_name,
            "BatchSize": 1,
            "StartingPosition": "TRIM_HORIZON",
            "EventSourceArn": stream_arn,
            "MaximumBatchingWindowInSeconds": 1,
            "MaximumRetryAttempts": 1,
            "FilterCriteria": {
                "Filters": [
                    {"Pattern": filter},
                ]
            },
        }

        with pytest.raises(Exception) as expected:
            lambda_client.create_event_source_mapping(**event_source_mapping_kwargs)
        snapshot.match("exception_event_source_creation", expected.value.response)
        expected.match(INVALID_PARAMETER_VALUE_EXCEPTION)
