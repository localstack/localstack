import json
import time

import pytest

from localstack.services.awslambda.lambda_api import INVALID_PARAMETER_VALUE_EXCEPTION
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON37, LAMBDA_RUNTIME_PYTHON39
from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry, poll_condition
from localstack.utils.testutil import check_expected_lambda_log_events_length, get_lambda_log_events
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO, TEST_LAMBDA_PYTHON_UNHANDLED_ERROR
from localstack.testing.aws.lambda_utils import lambda_role, s3_lambda_permission, _await_event_source_mapping_enabled, \
    _await_dynamodb_table_active


class TestDynamoDBEventSourceMapping:
    def test_dynamodb_event_source_mapping(
        self,
        lambda_client,
        create_lambda_function,
        create_iam_role_with_policy,
        dynamodb_client,
        dynamodb_create_table,
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

        uuid = None

        try:
            create_lambda_function(
                func_name=function_name,
                handler_file=TEST_LAMBDA_PYTHON_ECHO,
                runtime=LAMBDA_RUNTIME_PYTHON37,
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
            if uuid:
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
                runtime=LAMBDA_RUNTIME_PYTHON39,
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
    ):

        function_name = f"lambda_func-{short_uid()}"
        table_name = f"test-table-{short_uid()}"
        event_source_uuid = None
        max_retries = 50

        try:

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
            }
            event_source_mapping_kwargs.update(
                FilterCriteria={
                    "Filters": [
                        {"Pattern": json.dumps(filter)},
                    ]
                }
            )

            event_source_uuid = lambda_client.create_event_source_mapping(
                **event_source_mapping_kwargs
            )["UUID"]

            _await_event_source_mapping_enabled(lambda_client, event_source_uuid)
            dynamodb_client.put_item(TableName=table_name, Item=item_to_put1)

            def assert_lambda_called():
                events = get_lambda_log_events(function_name, logs_client=logs_client)
                if calls > 0:
                    assert len(events) == 1
                else:
                    # negative test for 'numeric' filter
                    assert len(events) == 0

            retry(assert_lambda_called, retries=max_retries)

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

                # lambda was called a second time, so new records should be found
                retry(assert_events_called_multiple, retries=max_retries)
            else:
                # lambda wasn't called a second time, so no new records should be found
                retry(assert_lambda_called, retries=max_retries)

        finally:
            if event_source_uuid:
                lambda_client.delete_event_source_mapping(UUID=event_source_uuid)

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
        expected.match(INVALID_PARAMETER_VALUE_EXCEPTION)
