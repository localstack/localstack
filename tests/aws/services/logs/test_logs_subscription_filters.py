"""Tests for CloudWatch Logs - Subscription Filter operations."""

import base64
import gzip
import json
import re

import pytest
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.config import TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.aws.arns import get_partition
from localstack.utils.common import now_utc, retry, short_uid
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO

# IAM role and policy definitions for cross-service integration
logs_role = {
    "Statement": {
        "Effect": "Allow",
        "Principal": {"Service": f"logs.{TEST_AWS_REGION_NAME}.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}

kinesis_permission = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "kinesis:PutRecord", "Resource": "*"}],
}

s3_firehose_role = {
    "Statement": {
        "Sid": "",
        "Effect": "Allow",
        "Principal": {"Service": "firehose.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }
}

s3_firehose_permission = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:*", "s3-object-lambda:*"], "Resource": "*"}],
}

firehose_permission = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["firehose:*"], "Resource": "*"}],
}


def _subscription_filter_exists(filters: list, name: str) -> bool:
    """Check if a subscription filter with the given name exists in the list."""
    return any(f["filterName"] == name for f in filters)


class TestSubscriptionFilters:
    """Tests for subscription filter operations."""

    @markers.aws.validated
    def test_describe_subscription_filters_empty(self, logs_log_group, aws_client, snapshot):
        """Test describing subscription filters when none exist."""
        snapshot.add_transformer(snapshot.transform.logs_api())
        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        snapshot.match("describe-subscription-filters-empty", response)

    @markers.aws.validated
    def test_describe_subscription_filters_log_group_not_found(self, aws_client, snapshot):
        """Test describing subscription filters for non-existent log group."""
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_subscription_filters(logGroupName="not-existing-log-group")
        snapshot.match("error-log-group-not-found", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Statement.Condition.StringEquals",
            "$..add_permission.ResponseMetadata.HTTPStatusCode",
            "$..subscriptionFilters..applyOnTransformedLogs",
        ]
    )
    def test_put_subscription_filter_lambda(
        self,
        logs_log_group,
        logs_log_stream,
        create_lambda_function,
        snapshot,
        aws_client,
        region_name,
    ):
        """Test putting a subscription filter with Lambda destination."""
        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(snapshot.transform.key_value("logGroupName"))
        snapshot.add_transformer(snapshot.transform.key_value("logStreamName"))
        snapshot.add_transformer(
            KeyValueBasedTransformer(
                lambda k, v: (
                    v
                    if k == "id" and (isinstance(v, str) and re.match(re.compile(r"^[0-9]+$"), v))
                    else None
                ),
                replacement="id",
                replace_reference=False,
            ),
        )

        test_lambda_name = f"test-lambda-function-{short_uid()}"
        func_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=test_lambda_name,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]["FunctionArn"]

        aws_client.lambda_.invoke(FunctionName=test_lambda_name, Payload=b"{}")

        # Get account-id to set the correct policy
        account_id = aws_client.sts.get_caller_identity()["Account"]
        result = aws_client.lambda_.add_permission(
            FunctionName=test_lambda_name,
            StatementId=test_lambda_name,
            Principal=f"logs.{region_name}.amazonaws.com",
            Action="lambda:InvokeFunction",
            SourceArn=f"arn:{get_partition(region_name)}:logs:{region_name}:{account_id}:log-group:{logs_log_group}:*",
            SourceAccount=account_id,
        )
        snapshot.match("add_permission", result)

        result = aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test",
            filterPattern="",
            destinationArn=func_arn,
        )
        snapshot.match("put_subscription_filter", result)

        aws_client.logs.put_log_events(
            logGroupName=logs_log_group,
            logStreamName=logs_log_stream,
            logEvents=[
                {"timestamp": now_utc(millis=True), "message": "test"},
                {"timestamp": now_utc(millis=True), "message": "test 2"},
            ],
        )

        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        assert len(response["subscriptionFilters"]) == 1
        snapshot.match("describe_subscription_filter", response)

        def check_invocation():
            events = testutil.list_all_log_events(
                log_group_name=f"/aws/lambda/{test_lambda_name}", logs_client=aws_client.logs
            )
            # We only are interested in events that contain "awslogs"
            filtered_events = []
            for e in events:
                if "awslogs" in e["message"]:
                    data = json.loads(e["message"])["awslogs"]["data"].encode("utf-8")
                    decoded_data = gzip.decompress(base64.b64decode(data)).decode("utf-8")
                    for log_event in json.loads(decoded_data)["logEvents"]:
                        filtered_events.append(log_event)
            assert len(filtered_events) == 2

            filtered_events.sort(key=lambda k: k.get("message"))
            snapshot.match("list_all_log_events", filtered_events)

        retry(check_invocation, retries=6, sleep=3.0)

    @markers.aws.validated
    def test_put_subscription_filter_kinesis(
        self, logs_log_group, logs_log_stream, create_iam_role_with_policy, aws_client
    ):
        """Test putting a subscription filter with Kinesis destination."""
        kinesis_name = f"test-kinesis-{short_uid()}"
        filter_name = "Destination"
        aws_client.kinesis.create_stream(StreamName=kinesis_name, ShardCount=1)

        try:
            result = aws_client.kinesis.describe_stream(StreamName=kinesis_name)[
                "StreamDescription"
            ]
            kinesis_arn = result["StreamARN"]
            role = f"test-kinesis-role-{short_uid()}"
            policy_name = f"test-kinesis-role-policy-{short_uid()}"
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=logs_role,
                PolicyDefinition=kinesis_permission,
            )

            # Wait for stream-status "ACTIVE"
            status = result["StreamStatus"]
            if status != "ACTIVE":

                def check_stream_active():
                    state = aws_client.kinesis.describe_stream(StreamName=kinesis_name)[
                        "StreamDescription"
                    ]["StreamStatus"]
                    if state != "ACTIVE":
                        raise Exception(f"StreamStatus is {state}")

                retry(check_stream_active, retries=6, sleep=1.0, sleep_before=2.0)

            def put_subscription_filter():
                aws_client.logs.put_subscription_filter(
                    logGroupName=logs_log_group,
                    filterName=filter_name,
                    filterPattern="",
                    destinationArn=kinesis_arn,
                    roleArn=role_arn,
                )

            retry(put_subscription_filter, retries=6, sleep=3.0)

            def put_event():
                aws_client.logs.put_log_events(
                    logGroupName=logs_log_group,
                    logStreamName=logs_log_stream,
                    logEvents=[
                        {"timestamp": now_utc(millis=True), "message": "test"},
                        {"timestamp": now_utc(millis=True), "message": "test 2"},
                    ],
                )

            retry(put_event, retries=6, sleep=3.0)

            shard_iterator = aws_client.kinesis.get_shard_iterator(
                StreamName=kinesis_name,
                ShardId="shardId-000000000000",
                ShardIteratorType="TRIM_HORIZON",
            )["ShardIterator"]

            response = aws_client.kinesis.get_records(ShardIterator=shard_iterator)
            # AWS sends messages as health checks
            assert len(response["Records"]) >= 1
            found = False
            for record in response["Records"]:
                data = record["Data"]
                unzipped_data = gzip.decompress(data)
                json_data = json.loads(unzipped_data)
                if "test" in json.dumps(json_data["logEvents"]):
                    assert len(json_data["logEvents"]) == 2
                    assert json_data["logEvents"][0]["message"] == "test"
                    assert json_data["logEvents"][1]["message"] == "test 2"
                    found = True

            assert found
        finally:
            aws_client.kinesis.delete_stream(StreamName=kinesis_name, EnforceConsumerDeletion=True)
            aws_client.logs.delete_subscription_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )

    @markers.aws.validated
    def test_put_subscription_filter_firehose(
        self, logs_log_group, logs_log_stream, s3_bucket, create_iam_role_with_policy, aws_client
    ):
        """Test putting a subscription filter with Firehose destination."""
        try:
            firehose_name = f"test-firehose-{short_uid()}"
            s3_bucket_arn = f"arn:aws:s3:::{s3_bucket}"

            role = f"test-firehose-s3-role-{short_uid()}"
            policy_name = f"test-firehose-s3-role-policy-{short_uid()}"
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=s3_firehose_role,
                PolicyDefinition=s3_firehose_permission,
            )

            # AWS has troubles creating the delivery stream the first time
            def create_delivery_stream():
                aws_client.firehose.create_delivery_stream(
                    DeliveryStreamName=firehose_name,
                    S3DestinationConfiguration={
                        "BucketARN": s3_bucket_arn,
                        "RoleARN": role_arn,
                        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                    },
                )

            retry(create_delivery_stream, retries=5, sleep=10.0)

            response = aws_client.firehose.describe_delivery_stream(
                DeliveryStreamName=firehose_name
            )
            firehose_arn = response["DeliveryStreamDescription"]["DeliveryStreamARN"]

            role = f"test-firehose-role-{short_uid()}"
            policy_name = f"test-firehose-role-policy-{short_uid()}"
            role_arn_logs = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=logs_role,
                PolicyDefinition=firehose_permission,
            )

            def check_stream_active():
                state = aws_client.firehose.describe_delivery_stream(
                    DeliveryStreamName=firehose_name
                )["DeliveryStreamDescription"]["DeliveryStreamStatus"]
                if state != "ACTIVE":
                    raise Exception(f"DeliveryStreamStatus is {state}")

            retry(check_stream_active, retries=60, sleep=30.0)

            aws_client.logs.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="Destination",
                filterPattern="",
                destinationArn=firehose_arn,
                roleArn=role_arn_logs,
            )

            aws_client.logs.put_log_events(
                logGroupName=logs_log_group,
                logStreamName=logs_log_stream,
                logEvents=[
                    {"timestamp": now_utc(millis=True), "message": "test"},
                    {"timestamp": now_utc(millis=True), "message": "test 2"},
                ],
            )

            def list_objects():
                response = aws_client.s3.list_objects(Bucket=s3_bucket)
                assert len(response["Contents"]) >= 1

            retry(list_objects, retries=60, sleep=30.0)
            response = aws_client.s3.list_objects(Bucket=s3_bucket)
            key = response["Contents"][-1]["Key"]
            response = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
            content = gzip.decompress(response["Body"].read()).decode("utf-8")
            assert "DATA_MESSAGE" in content
            assert "test" in content
            assert "test 2" in content

        finally:
            aws_client.firehose.delete_delivery_stream(
                DeliveryStreamName=firehose_name, AllowForceDelete=True
            )


class TestSubscriptionFilterUpdates:
    """Tests for subscription filter update and delete operations."""

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..subscriptionFilters..applyOnTransformedLogs"])
    def test_put_subscription_filter_update(
        self, logs_log_group, create_lambda_function, aws_client, region_name, snapshot
    ):
        """Test updating a subscription filter."""
        test_lambda_name = f"test-lambda-{short_uid()}"
        func_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=test_lambda_name,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]["FunctionArn"]

        account_id = aws_client.sts.get_caller_identity()["Account"]
        aws_client.lambda_.add_permission(
            FunctionName=test_lambda_name,
            StatementId=test_lambda_name,
            Principal=f"logs.{region_name}.amazonaws.com",
            Action="lambda:InvokeFunction",
            SourceArn=f"arn:{get_partition(region_name)}:logs:{region_name}:{account_id}:log-group:{logs_log_group}:*",
            SourceAccount=account_id,
        )

        # Create initial subscription filter
        aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test",
            filterPattern="",
            destinationArn=func_arn,
        )

        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        assert len(response["subscriptionFilters"]) == 1

        # Update subscription filter (same filterName)
        aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test",
            filterPattern="[]",
            destinationArn=func_arn,
        )

        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        snapshot.add_transformer(snapshot.transform.regex(func_arn, "<function-arn>"))
        snapshot.add_transformer(snapshot.transform.regex(logs_log_group, "<log-group-name>"))
        snapshot.match("updated-filter", response)

    @markers.aws.validated
    def test_put_subscription_filter_limit_exceeded(
        self, logs_log_group, create_lambda_function, aws_client, region_name, snapshot, account_id
    ):
        """Test that only 2 subscription filters can be associated with a log group."""
        test_lambda_name = f"test-lambda-{short_uid()}"
        func_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=test_lambda_name,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]["FunctionArn"]

        aws_client.lambda_.add_permission(
            FunctionName=test_lambda_name,
            StatementId=test_lambda_name,
            Principal=f"logs.{region_name}.amazonaws.com",
            Action="lambda:InvokeFunction",
            SourceArn=f"arn:{get_partition(region_name)}:logs:{region_name}:{account_id}:log-group:{logs_log_group}:*",
            SourceAccount=account_id,
        )

        # Create first subscription filter
        aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test-1",
            filterPattern="",
            destinationArn=func_arn,
        )

        # Create second subscription filter
        aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test-2",
            filterPattern="[]",
            destinationArn=func_arn,
        )

        # Third should fail
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="test-3",
                filterPattern="",
                destinationArn=func_arn,
            )
        snapshot.match("error-limit-exceeded", ctx.value.response)

    @markers.aws.validated
    def test_delete_subscription_filter(
        self, logs_log_group, create_lambda_function, aws_client, region_name
    ):
        """Test deleting a subscription filter."""
        test_lambda_name = f"test-lambda-{short_uid()}"
        func_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=test_lambda_name,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]["FunctionArn"]

        account_id = aws_client.sts.get_caller_identity()["Account"]
        aws_client.lambda_.add_permission(
            FunctionName=test_lambda_name,
            StatementId=test_lambda_name,
            Principal=f"logs.{region_name}.amazonaws.com",
            Action="lambda:InvokeFunction",
            SourceArn=f"arn:{get_partition(region_name)}:logs:{region_name}:{account_id}:log-group:{logs_log_group}:*",
            SourceAccount=account_id,
        )

        aws_client.logs.put_subscription_filter(
            logGroupName=logs_log_group,
            filterName="test",
            filterPattern="",
            destinationArn=func_arn,
        )

        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        assert len(response["subscriptionFilters"]) == 1

        # Delete subscription filter
        aws_client.logs.delete_subscription_filter(logGroupName=logs_log_group, filterName="test")

        response = aws_client.logs.describe_subscription_filters(logGroupName=logs_log_group)
        assert len(response["subscriptionFilters"]) == 0

    @markers.aws.validated
    def test_delete_subscription_filter_errors(self, logs_log_group, aws_client, snapshot):
        """Test delete subscription filter error handling."""
        # Non-existent log group
        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_subscription_filter(
                logGroupName="not-existing-log-group", filterName="test"
            )
        snapshot.match("error-log-group-not-found", ctx.value.response)

        # Non-existent filter
        with pytest.raises(Exception) as ctx:
            aws_client.logs.delete_subscription_filter(
                logGroupName=logs_log_group, filterName="wrong-filter-name"
            )
        snapshot.match("error-filter-not-found", ctx.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Code", "$..Error.Message"])
    def test_put_subscription_filter_errors(
        self, logs_log_group, create_lambda_function, aws_client, snapshot
    ):
        """Test put subscription filter error handling."""
        # Non-existent log group
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_subscription_filter(
                logGroupName="not-existing-log-group",
                filterName="test",
                filterPattern="",
                destinationArn="arn:aws:lambda:us-east-1:123456789012:function:test",
            )
        snapshot.match("error-log-group-not-found", ctx.value.response)

        # Non-existent Lambda function
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="test",
                filterPattern="",
                destinationArn="arn:aws:lambda:us-east-1:123456789012:function:not-existing",
            )
        snapshot.match("error-lambda-not-found", ctx.value.response)

        # Non-existent Kinesis stream
        with pytest.raises(Exception) as ctx:
            aws_client.logs.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="test",
                filterPattern="",
                destinationArn="arn:aws:kinesis:us-east-1:123456789012:stream/unknown-stream",
            )
        snapshot.match("error-kinesis-not-found", ctx.value.response)
