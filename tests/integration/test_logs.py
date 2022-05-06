# -*- coding: utf-8 -*-
import gzip
import json

import pytest

from localstack import config
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import now_utc, poll_condition, retry, short_uid

from .awslambda.test_lambda import TEST_LAMBDA_LIBS, TEST_LAMBDA_PYTHON3

logs_role = {
    "Statement": {
        "Effect": "Allow",
        "Principal": {"Service": f"logs.{config.DEFAULT_REGION}.amazonaws.com"},
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


@pytest.fixture
def logs_log_group(logs_client):
    name = f"test-log-group-{short_uid()}"
    logs_client.create_log_group(logGroupName=name)
    yield name
    logs_client.delete_log_group(logGroupName=name)


@pytest.fixture
def logs_log_stream(logs_client, logs_log_group):
    name = f"test-log-stream-{short_uid()}"
    logs_client.create_log_stream(logGroupName=logs_log_group, logStreamName=name)
    yield name
    logs_client.delete_log_stream(logStreamName=name, logGroupName=logs_log_group)


class TestCloudWatchLogs:
    # TODO make creation and description atomic to avoid possible flake?
    def test_create_and_delete_log_group(self, logs_client):
        test_name = f"test-log-group-{short_uid()}"
        log_groups_before = logs_client.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])

        logs_client.create_log_group(logGroupName=test_name)

        log_groups_between = logs_client.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])
        assert poll_condition(
            lambda: len(log_groups_between) == len(log_groups_before) + 1, timeout=5.0, interval=0.5
        )

        logs_client.delete_log_group(logGroupName=test_name)

        log_groups_after = logs_client.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])
        assert poll_condition(
            lambda: len(log_groups_after) == len(log_groups_between) - 1, timeout=5.0, interval=0.5
        )
        assert len(log_groups_after) == len(log_groups_before)

    def test_list_tags_log_group(self, logs_client):
        test_name = f"test-log-group-{short_uid()}"
        logs_client.create_log_group(logGroupName=test_name, tags={"env": "testing1"})

        response = logs_client.list_tags_log_group(logGroupName=test_name)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert "tags" in response
        assert response["tags"]["env"] == "testing1"

        # clean up
        logs_client.delete_log_group(logGroupName=test_name)

    def test_create_and_delete_log_stream(self, logs_client, logs_log_group):
        test_name = f"test-log-stream-{short_uid()}"
        log_streams_before = logs_client.describe_log_streams(logGroupName=logs_log_group).get(
            "logStreams", []
        )

        logs_client.create_log_stream(logGroupName=logs_log_group, logStreamName=test_name)

        log_streams_between = logs_client.describe_log_streams(logGroupName=logs_log_group).get(
            "logStreams", []
        )
        assert poll_condition(
            lambda: len(log_streams_between) == len(log_streams_before) + 1,
            timeout=5.0,
            interval=0.5,
        )

        logs_client.delete_log_stream(logGroupName=logs_log_group, logStreamName=test_name)

        log_streams_after = logs_client.describe_log_streams(logGroupName=logs_log_group).get(
            "logStreams", []
        )
        assert poll_condition(
            lambda: len(log_streams_between) - 1 == len(log_streams_after),
            timeout=5.0,
            interval=0.5,
        )
        assert len(log_streams_after) == len(log_streams_before)

    def test_put_events_multi_bytes_msg(self, logs_client, logs_log_group, logs_log_stream):
        body_msg = "🙀 - 参よ - 日本語"
        events = [{"timestamp": now_utc(millis=True), "message": body_msg}]
        response = logs_client.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        events = logs_client.get_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream
        )["events"]
        assert events[0]["message"] == body_msg

    def test_filter_log_events_response_header(self, logs_client, logs_log_group, logs_log_stream):
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        response = logs_client.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        response = logs_client.filter_log_events(logGroupName=logs_log_group)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert (
            response["ResponseMetadata"]["HTTPHeaders"]["content-type"] == APPLICATION_AMZ_JSON_1_1
        )

    def test_put_subscription_filter_lambda(
        self,
        lambda_client,
        logs_client,
        logs_log_group,
        logs_log_stream,
        create_lambda_function,
        sts_client,
    ):
        test_lambda_name = f"test-lambda-function-{short_uid()}"
        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON3,
            libs=TEST_LAMBDA_LIBS,
            func_name=test_lambda_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        try:
            lambda_client.invoke(FunctionName=test_lambda_name, Payload=b"{}")
            # get account-id to set the correct policy
            account_id = sts_client.get_caller_identity()["Account"]
            lambda_client.add_permission(
                FunctionName=test_lambda_name,
                StatementId=test_lambda_name,
                Principal=f"logs.{config.DEFAULT_REGION}.amazonaws.com",
                Action="lambda:InvokeFunction",
                SourceArn=f"arn:aws:logs:{config.DEFAULT_REGION}:{account_id}:log-group:{logs_log_group}:*",
                SourceAccount=account_id,
            )
            logs_client.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="test",
                filterPattern="",
                destinationArn=aws_stack.lambda_function_arn(
                    test_lambda_name, account_id=account_id, region_name=config.DEFAULT_REGION
                ),
            )

            logs_client.put_log_events(
                logGroupName=logs_log_group,
                logStreamName=logs_log_stream,
                logEvents=[
                    {"timestamp": now_utc(millis=True), "message": "test"},
                    {"timestamp": now_utc(millis=True), "message": "test 2"},
                ],
            )

            response = logs_client.describe_subscription_filters(logGroupName=logs_log_group)
            assert len(response["subscriptionFilters"]) == 1

            def check_invocation():
                events = testutil.get_lambda_log_events(
                    test_lambda_name, log_group=logs_log_group, logs_client=logs_client
                )
                assert len(events) == 2
                assert "test" in events
                assert "test 2" in events

            retry(check_invocation, retries=6, sleep=3.0)
        finally:
            # clean up lambda log group
            log_group_name = f"/aws/lambda/{test_lambda_name}"
            logs_client.delete_log_group(logGroupName=log_group_name)

    def test_put_subscription_filter_firehose(
        self,
        logs_client,
        logs_log_group,
        logs_log_stream,
        s3_bucket,
        s3_client,
        firehose_client,
        iam_client,
        create_iam_role_with_policy,
    ):
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

            # TODO AWS has troubles creating the delivery stream the first time
            # policy is not accepted at first, so we try again
            def create_delivery_stream():
                firehose_client.create_delivery_stream(
                    DeliveryStreamName=firehose_name,
                    S3DestinationConfiguration={
                        "BucketARN": s3_bucket_arn,
                        "RoleARN": role_arn,
                        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                    },
                )

            retry(create_delivery_stream, retries=5, sleep=10.0)

            response = firehose_client.describe_delivery_stream(DeliveryStreamName=firehose_name)
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
                state = firehose_client.describe_delivery_stream(DeliveryStreamName=firehose_name)[
                    "DeliveryStreamDescription"
                ]["DeliveryStreamStatus"]
                if state != "ACTIVE":
                    raise Exception(f"DeliveryStreamStatus is {state}")

            retry(check_stream_active, retries=60, sleep=30.0)

            logs_client.put_subscription_filter(
                logGroupName=logs_log_group,
                filterName="Destination",
                filterPattern="",
                destinationArn=firehose_arn,
                roleArn=role_arn_logs,
            )

            logs_client.put_log_events(
                logGroupName=logs_log_group,
                logStreamName=logs_log_stream,
                logEvents=[
                    {"timestamp": now_utc(millis=True), "message": "test"},
                    {"timestamp": now_utc(millis=True), "message": "test 2"},
                ],
            )

            def list_objects():
                response = s3_client.list_objects(Bucket=s3_bucket)
                assert len(response["Contents"]) >= 1

            retry(list_objects, retries=60, sleep=30.0)
            response = s3_client.list_objects(Bucket=s3_bucket)
            key = response["Contents"][-1]["Key"]
            response = s3_client.get_object(Bucket=s3_bucket, Key=key)
            content = gzip.decompress(response["Body"].read()).decode("utf-8")
            assert "DATA_MESSAGE" in content
            assert "test" in content
            assert "test 2" in content

        finally:
            # clean up
            firehose_client.delete_delivery_stream(
                DeliveryStreamName=firehose_name, AllowForceDelete=True
            )

    def test_put_subscription_filter_kinesis(
        self,
        logs_client,
        logs_log_group,
        logs_log_stream,
        kinesis_client,
        iam_client,
        create_iam_role_with_policy,
    ):

        kinesis_name = f"test-kinesis-{short_uid()}"
        filter_name = "Destination"
        kinesis_client.create_stream(StreamName=kinesis_name, ShardCount=1)

        try:
            result = kinesis_client.describe_stream(StreamName=kinesis_name)["StreamDescription"]
            kinesis_arn = result["StreamARN"]
            role = f"test-kinesis-role-{short_uid()}"
            policy_name = f"test-kinesis-role-policy-{short_uid()}"
            role_arn = create_iam_role_with_policy(
                RoleName=role,
                PolicyName=policy_name,
                RoleDefinition=logs_role,
                PolicyDefinition=kinesis_permission,
            )

            # wait for stream-status "ACTIVE"
            status = result["StreamStatus"]
            if status != "ACTIVE":

                def check_stream_active():
                    state = kinesis_client.describe_stream(StreamName=kinesis_name)[
                        "StreamDescription"
                    ]["StreamStatus"]
                    if state != "ACTIVE":
                        raise Exception(f"StreamStatus is {state}")

                retry(check_stream_active, retries=6, sleep=1.0, sleep_before=2.0)

            def put_subscription_filter():
                logs_client.put_subscription_filter(
                    logGroupName=logs_log_group,
                    filterName=filter_name,
                    filterPattern="",
                    destinationArn=kinesis_arn,
                    roleArn=role_arn,
                )

            # for a weird reason the put_subscription_filter fails on AWS the first time,
            # even-though we check for ACTIVE state...
            retry(put_subscription_filter, retries=6, sleep=3.0)

            def put_event():
                logs_client.put_log_events(
                    logGroupName=logs_log_group,
                    logStreamName=logs_log_stream,
                    logEvents=[
                        {"timestamp": now_utc(millis=True), "message": "test"},
                        {"timestamp": now_utc(millis=True), "message": "test 2"},
                    ],
                )

            retry(put_event, retries=6, sleep=3.0)

            shard_iterator = kinesis_client.get_shard_iterator(
                StreamName=kinesis_name,
                ShardId="shardId-000000000000",
                ShardIteratorType="TRIM_HORIZON",
            )["ShardIterator"]

            response = kinesis_client.get_records(ShardIterator=shard_iterator)
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
        # clean up
        finally:
            kinesis_client.delete_stream(StreamName=kinesis_name, EnforceConsumerDeletion=True)
            logs_client.delete_subscription_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )

    @pytest.mark.skip("TODO: failing against pro")
    def test_metric_filters(self, logs_client, logs_log_group, logs_log_stream, cloudwatch_client):
        basic_filter_name = f"test-filter-basic-{short_uid()}"
        json_filter_name = f"test-filter-json-{short_uid()}"
        namespace_name = f"test-metric-namespace-{short_uid()}"
        basic_metric_name = f"test-basic-metric-{short_uid()}"
        json_metric_name = f"test-json-metric-{short_uid()}"
        basic_transforms = {
            "metricNamespace": namespace_name,
            "metricName": basic_metric_name,
            "metricValue": "1",
            "defaultValue": 0,
        }
        json_transforms = {
            "metricNamespace": namespace_name,
            "metricName": json_metric_name,
            "metricValue": "1",
            "defaultValue": 0,
        }
        logs_client.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=basic_filter_name,
            filterPattern=" ",
            metricTransformations=[basic_transforms],
        )
        logs_client.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=json_filter_name,
            filterPattern='{$.message = "test"}',
            metricTransformations=[json_transforms],
        )

        response = logs_client.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix="test-filter-"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        filter_names = [_filter["filterName"] for _filter in response["metricFilters"]]
        assert basic_filter_name in filter_names
        assert json_filter_name in filter_names

        # put log events and assert metrics being published
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        logs_client.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        # list metrics
        response = cloudwatch_client.list_metrics(Namespace=namespace_name)
        assert len(response["Metrics"]) == 2

        # delete filters
        logs_client.delete_metric_filter(logGroupName=logs_log_group, filterName=basic_filter_name)
        logs_client.delete_metric_filter(logGroupName=logs_log_group, filterName=json_filter_name)

        response = logs_client.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix="test-filter-"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        filter_names = [_filter["filterName"] for _filter in response["metricFilters"]]
        assert basic_filter_name not in filter_names
        assert json_filter_name not in filter_names

    def test_delivery_logs_for_sns(
        self, logs_client, sns_client, sns_create_topic, sns_subscription
    ):
        topic_name = f"test-logs-{short_uid()}"
        contact = "+10123456789"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=contact)

        message = "Good news everyone!"
        sns_client.publish(Message=message, TopicArn=topic_arn)
        logs_group_name = topic_arn.replace("arn:aws:", "").replace(":", "/")

        def log_group_exists():
            response = logs_client.describe_log_streams(logGroupName=logs_group_name)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        retry(log_group_exists)
