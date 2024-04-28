import json
import math
import time

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack.aws.api.lambda_ import InvalidParameterValueException, Runtime
from localstack.testing.aws.lambda_utils import (
    _await_dynamodb_table_active,
    _await_event_source_mapping_enabled,
    _get_lambda_invocation_events,
    lambda_role,
    s3_lambda_permission,
)
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events
from tests.aws.services.lambda_.test_lambda import (
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
def get_lambda_logs_event(aws_client):
    def _get_lambda_logs_event(function_name, expected_num_events, retries=30):
        return _get_lambda_invocation_events(
            logs_client=aws_client.logs,
            function_name=function_name,
            expected_num_events=expected_num_events,
            retries=retries,
        )

    return _get_lambda_logs_event


@markers.snapshot.skip_snapshot_verify(
    paths=[
        # dynamodb issues, not related to lambda
        "$..TableDescription.BillingModeSummary.LastUpdateToPayPerRequestDateTime",
        "$..TableDescription.DeletionProtectionEnabled",
        "$..TableDescription.ProvisionedThroughput.LastDecreaseDateTime",
        "$..TableDescription.ProvisionedThroughput.LastIncreaseDateTime",
        "$..TableDescription.StreamSpecification",
        "$..TableDescription.TableStatus",
        "$..Records..dynamodb.SizeBytes",
        "$..Records..eventVersion",
    ],
)
class TestDynamoDBEventSourceMapping:
    @markers.aws.validated
    def test_dynamodb_event_source_mapping(
        self,
        create_lambda_function,
        create_iam_role_with_policy,
        dynamodb_create_table,
        get_lambda_logs_event,
        cleanups,
        wait_for_dynamodb_stream_ready,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        role = f"test-lambda-role-{short_uid()}"
        policy_name = f"test-lambda-policy-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"
        db_item = {partition_key: {"S": "hello world"}, "binary_key": {"B": b"foobar"}}
        role_arn = create_iam_role_with_policy(
            RoleName=role,
            PolicyName=policy_name,
            RoleDefinition=lambda_role,
            PolicyDefinition=s3_lambda_permission,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=role_arn,
        )
        create_table_result = dynamodb_create_table(
            table_name=table_name, partition_key=partition_key
        )
        # snapshot create table to get the table name registered as resource
        snapshot.match("create-table-result", create_table_result)
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        stream_arn = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )["TableDescription"]["LatestStreamArn"]
        assert wait_for_dynamodb_stream_ready(stream_arn)
        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function_name,
            BatchSize=1,
            StartingPosition="TRIM_HORIZON",  # TODO investigate how to get it back to LATEST
            EventSourceArn=stream_arn,
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)
        event_source_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_uuid)
        )

        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_uuid)

        def _send_and_receive_events():
            aws_client.dynamodb.put_item(TableName=table_name, Item=db_item)
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

    @markers.aws.validated
    def test_duplicate_event_source_mappings(
        self,
        create_lambda_function,
        lambda_su_role,
        create_event_source_mapping,
        dynamodb_create_table,
        wait_for_dynamodb_stream_ready,
        snapshot,
        aws_client,
        cleanups,
    ):
        function_name_1 = f"lambda_func-{short_uid()}"
        function_name_2 = f"lambda_func-{short_uid()}"

        table_name = f"test-table-{short_uid()}"
        partition_key = "my_partition_key"

        create_table_result = dynamodb_create_table(
            table_name=table_name, partition_key=partition_key
        )
        # snapshot create table to get the table name registered as resource
        snapshot.match("create-table-result", create_table_result)
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        event_source_arn = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )["TableDescription"]["LatestStreamArn"]

        # extra arguments for create_event_source_mapping calls
        kwargs = dict(
            StartingPosition="TRIM_HORIZON",
            MaximumBatchingWindowInSeconds=1,
            MaximumRetryAttempts=1,
        )

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_1,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )

        response = create_event_source_mapping(
            FunctionName=function_name_1,
            EventSourceArn=event_source_arn,
            **kwargs,
        )
        snapshot.match("create", response)

        with pytest.raises(ClientError) as e:
            create_event_source_mapping(
                FunctionName=function_name_1,
                EventSourceArn=event_source_arn,
                **kwargs,
            )

        response = e.value.response
        snapshot.match("error", response)

        # this should work without problem since it's a new function
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name_2,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        create_event_source_mapping(
            FunctionName=function_name_2,
            EventSourceArn=event_source_arn,
            **kwargs,
        )

    @markers.aws.validated
    def test_disabled_dynamodb_event_source_mapping(
        self,
        create_lambda_function,
        dynamodb_create_table,
        lambda_su_role,
        cleanups,
        wait_for_dynamodb_stream_ready,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        ddb_table = f"ddb_table-{short_uid()}"
        items = [
            {"id": {"S": short_uid()}, "data": {"S": "data1"}},
            {"id": {"S": short_uid()}, "data": {"S": "data2"}},
        ]
        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        dynamodb_create_table_result = dynamodb_create_table(
            table_name=ddb_table, partition_key="id", stream_view_type="NEW_IMAGE"
        )
        latest_stream_arn = dynamodb_create_table_result["TableDescription"]["LatestStreamArn"]
        snapshot.match("dynamodb_create_table_result", dynamodb_create_table_result)
        rs = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=latest_stream_arn,
            StartingPosition="TRIM_HORIZON",
            MaximumBatchingWindowInSeconds=1,
        )
        snapshot.match("create_event_source_mapping_result", rs)
        uuid = rs["UUID"]
        cleanups.append(lambda: aws_client.lambda_.delete_event_source_mapping(UUID=uuid))
        _await_event_source_mapping_enabled(aws_client.lambda_, uuid)

        assert wait_for_dynamodb_stream_ready(latest_stream_arn)

        aws_client.dynamodb.put_item(TableName=ddb_table, Item=items[0])

        # Lambda should be invoked 1 time
        retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=3,
            function_name=function_name,
            expected_length=1,
            logs_client=aws_client.logs,
        )
        # disable event source mapping
        update_event_source_mapping_result = aws_client.lambda_.update_event_source_mapping(
            UUID=uuid, Enabled=False
        )
        snapshot.match("update_event_source_mapping_result", update_event_source_mapping_result)
        time.sleep(2)
        aws_client.dynamodb.put_item(TableName=ddb_table, Item=items[1])
        # lambda no longer invoked, still have 1 event
        check_expected_lambda_log_events_length(
            expected_length=1, function_name=function_name, logs_client=aws_client.logs
        )

    @markers.aws.validated
    def test_deletion_event_source_mapping_with_dynamodb(
        self,
        create_lambda_function,
        lambda_su_role,
        snapshot,
        cleanups,
        dynamodb_create_table,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        ddb_table = f"ddb_table-{short_uid()}"

        create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        create_dynamodb_table_response = dynamodb_create_table(
            table_name=ddb_table,
            partition_key="id",
            client=aws_client.dynamodb,
            stream_view_type="NEW_IMAGE",
        )
        snapshot.match("create_dynamodb_table_response", create_dynamodb_table_response)
        _await_dynamodb_table_active(aws_client.dynamodb, ddb_table)
        latest_stream_arn = create_dynamodb_table_response["TableDescription"]["LatestStreamArn"]
        result = aws_client.lambda_.create_event_source_mapping(
            FunctionName=function_name,
            EventSourceArn=latest_stream_arn,
            StartingPosition="TRIM_HORIZON",
        )
        snapshot.match("create_event_source_mapping_result", result)
        _await_event_source_mapping_enabled(aws_client.lambda_, result["UUID"])
        cleanups.append(lambda: aws_client.dynamodb.delete_table(TableName=ddb_table))

        event_source_mapping_uuid = result["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )
        aws_client.dynamodb.delete_table(TableName=ddb_table)
        list_esm = aws_client.lambda_.list_event_source_mappings(EventSourceArn=latest_stream_arn)
        snapshot.match("list_event_source_mapping_result", list_esm)

    @markers.aws.validated
    # FIXME last three skip verification entries are purely due to numbering mismatches
    @markers.snapshot.skip_snapshot_verify(
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
        create_lambda_function,
        sqs_get_queue_arn,
        sqs_create_queue,
        create_iam_role_with_policy,
        dynamodb_create_table,
        snapshot,
        cleanups,
        aws_client,
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
            runtime=Runtime.python3_9,
            role=role_arn,
        )
        dynamodb_create_table(table_name=table_name, partition_key=partition_key)
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        update_table_response = aws_client.dynamodb.update_table(
            TableName=table_name,
            StreamSpecification={"StreamEnabled": True, "StreamViewType": "NEW_IMAGE"},
        )
        snapshot.match("update_table_response", update_table_response)
        stream_arn = update_table_response["TableDescription"]["LatestStreamArn"]
        destination_queue = sqs_create_queue()
        queue_failure_event_source_mapping_arn = sqs_get_queue_arn(destination_queue)
        destination_config = {"OnFailure": {"Destination": queue_failure_event_source_mapping_arn}}
        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
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
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_mapping_uuid)
        )

        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_mapping_uuid)

        aws_client.dynamodb.put_item(TableName=table_name, Item=item)

        def verify_failure_received():
            res = aws_client.sqs.receive_message(QueueUrl=destination_queue)
            assert res.get("Messages")
            return res

        # It can take ~3 min against AWS until the message is received
        sleep = 10 if is_aws_cloud() else 5
        messages = retry(verify_failure_received, retries=15, sleep=sleep, sleep_before=5)
        snapshot.match("destination_queue_messages", messages)

    # TODO: consider re-designing this test case because it currently does negative testing for the second event,
    #  which can be unreliable due to undetermined waiting times (i.e., retries). For reliable testing, we need
    #  a) strict event ordering and b) a final event that passes all filters to reliably determine the end of the test.
    #  The current behavior leads to hard-to-detect false negatives such as in this CI run:
    #  https://app.circleci.com/pipelines/github/localstack/localstack/24012/workflows/461664c2-0203-45f9-aec2-394666f48f03/jobs/197705/tests
    @pytest.mark.parametrize(
        # Calls represents the expected number of Lambda invocations (either 1 or 2).
        # Negative tests with calls=0 are unreliable due to undetermined waiting times.
        "item_to_put1, item_to_put2, filter, calls",
        [
            # Test with filter, and two times same entry
            pytest.param(
                {"id": {"S": "id_value"}, "id2": {"S": "id2_value"}},
                # Inserting the same event (identified by PK) twice triggers a MODIFY event.
                {"id": {"S": "id_value"}, "id2": {"S": "id2_value"}},
                {"eventName": ["INSERT"]},
                1,
                id="insert_same_entry_twice",
            ),
            # Test with OR filter
            pytest.param(
                {"id": {"S": "id_value"}},
                {"id": {"S": "id_value"}, "id2": {"S": "id2_new_value"}},
                {"eventName": ["INSERT", "MODIFY"]},
                2,
                id="content_or_filter",
            ),
            # Test with 2 filters (AND), and two times same entry (second time modified aka MODIFY eventName)
            pytest.param(
                {"id": {"S": "id_value"}},
                {"id": {"S": "id_value"}, "id2": {"S": "id2_new_value"}},
                {"eventName": ["INSERT"], "eventSource": ["aws:dynamodb"]},
                1,
                id="content_multiple_filters",
            ),
            # Test content filter using the DynamoDB data type "S"
            pytest.param(
                {"id": {"S": "id_value_1"}, "presentKey": {"S": "presentValue"}},
                {"id": {"S": "id_value_2"}},
                # Omitting the "S" does NOT match: {"dynamodb": {"NewImage": {"presentKey": ["presentValue"]}}}
                {"dynamodb": {"NewImage": {"presentKey": {"S": ["presentValue"]}}}},
                1,
                id="content_filter_type",
            ),
            # Test exists filter using the DynamoDB data type "S"
            pytest.param(
                {"id": {"S": "id_value_1"}, "presentKey": {"S": "presentValue"}},
                {"id": {"S": "id_value_2"}},
                # Omitting the "S" does NOT match: {"dynamodb": {"NewImage": {"presentKey": [{"exists": True}]}}}
                {"dynamodb": {"NewImage": {"presentKey": {"S": [{"exists": True}]}}}},
                1,
                id="exists_filter_type",
            ),
            # TODO: Fix native LocalStack implementation for exists
            # pytest.param(
            #     {"id": {"S": "id_value_1"}},
            #     {"id": {"S": "id_value_2"}, "presentKey": {"S": "presentValue"}},
            #     {"dynamodb": {"NewImage": {"presentKey": [{"exists": False}]}}},
            #     2,
            #     id="exists_false_filter",
            # ),
            # numeric filter
            # NOTE: numeric filters do not work with DynamoDB because all values are represented as string
            # and not converted to numbers for filtering.
            # The following AWS tutorial has a note about numeric filtering, which does not apply to DynamoDB strings:
            # https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Streams.Lambda.Tutorial2.html
            # TODO: Fix native LocalStack implementation for anything-but
            # pytest.param(
            #     {"id": {"S": "id_value_1"}, "numericFilter": {"N": "42"}},
            #     {"id": {"S": "id_value_2"}, "numericFilter": {"N": "101"}},
            #     {
            #         "dynamodb": {
            #             "NewImage": {
            #                 "numericFilter": {
            #                     # Filtering passes if at least one of the filter conditions matches
            #                     "N": [{"numeric": [">", 100]}, {"anything-but": "101"}]
            #                 }
            #             }
            #         }
            #     },
            #     1,
            #     id="numeric_filter",
            # ),
            # Prefix
            pytest.param(
                {"id": {"S": "id_value_1"}, "prefix": {"S": "us-1-other-suffix"}},
                {"id": {"S": "id_value_1"}, "prefix": {"S": "other-suffix"}},
                {"dynamodb": {"NewImage": {"prefix": {"S": [{"prefix": "us-1"}]}}}},
                1,
                id="prefix_filter",
            ),
            # DynamoDB ApproximateCreationDateTime (datetime) gets converted into a float BEFORE filtering
            # https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-ddb
            # Using a numeric operator implicitly checks whether ApproximateCreationDateTime is a numeric type
            pytest.param(
                {"id": {"S": "id_value_1"}},
                {"id": {"S": "id_value_2"}},
                {"dynamodb": {"ApproximateCreationDateTime": [{"numeric": [">", 0]}]}},
                2,
                id="date_time_conversion",
            ),
        ],
    )
    @markers.aws.validated
    def test_dynamodb_event_filter(
        self,
        create_lambda_function,
        dynamodb_create_table,
        lambda_su_role,
        wait_for_dynamodb_stream_ready,
        filter,
        calls,
        item_to_put1,
        item_to_put2,
        cleanups,
        snapshot,
        aws_client,
    ):
        """Test event filtering for DynamoDB streams:
        https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html#filtering-ddb

        Slow against AWS taking ~2min per test case.

        Test assumption: The first item MUST always match the filter and the second item CAN match the filter.
        => This enables two-step testing (i.e., snapshots between inserts) but is unreliable and should be revised.
        """
        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        max_retries = 50

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        table_creation_response = dynamodb_create_table(table_name=table_name, partition_key="id")
        snapshot.match("table_creation_response", table_creation_response)
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        stream_arn = aws_client.dynamodb.update_table(
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

        create_event_source_mapping_response = aws_client.lambda_.create_event_source_mapping(
            **event_source_mapping_kwargs
        )
        event_source_uuid = create_event_source_mapping_response["UUID"]
        cleanups.append(
            lambda: aws_client.lambda_.delete_event_source_mapping(UUID=event_source_uuid)
        )
        snapshot.match("create_event_source_mapping_response", create_event_source_mapping_response)

        _await_event_source_mapping_enabled(aws_client.lambda_, event_source_uuid)

        # Insert item_to_put1
        aws_client.dynamodb.put_item(TableName=table_name, Item=item_to_put1)

        def assert_lambda_called():
            events = get_lambda_log_events(function_name, logs_client=aws_client.logs)
            assert len(events) == 1
            return events

        events = retry(assert_lambda_called, retries=max_retries)
        snapshot.match("lambda-log-events", events)

        # Insert item_to_put2
        aws_client.dynamodb.put_item(TableName=table_name, Item=item_to_put2)

        # The Lambda might be called multiple times depending on the items to put and filter.
        if calls > 1:

            def assert_events_called_multiple():
                events = get_lambda_log_events(function_name, logs_client=aws_client.logs)
                assert len(events) == calls
                return events

            # lambda was called a second time, so new records should be found
            events = retry(assert_events_called_multiple, retries=max_retries)
        else:
            # lambda wasn't called a second time, so no new records should be found
            events = retry(assert_lambda_called, retries=max_retries)

        # Validate events containing either one or two records
        for event in events:
            for record in event["Records"]:
                if creation_time := record.get("dynamodb", {}).get("ApproximateCreationDateTime"):
                    # Ensure the timestamp is in the right format (e.g., no unserializable datetime)
                    assert isinstance(creation_time, float)
        snapshot.match("lambda-multiple-log-events", events)

    @markers.aws.validated
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
        dynamodb_create_table,
        lambda_su_role,
        wait_for_dynamodb_stream_ready,
        filter,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_9,
            role=lambda_su_role,
        )
        dynamodb_create_table(table_name=table_name, partition_key="id")
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)
        stream_arn = aws_client.dynamodb.update_table(
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
            aws_client.lambda_.create_event_source_mapping(**event_source_mapping_kwargs)
        snapshot.match("exception_event_source_creation", expected.value.response)
        expected.match(InvalidParameterValueException.code)
