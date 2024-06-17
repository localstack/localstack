import base64
import gzip
import json
import re

import pytest
from localstack_snapshot.pytest.snapshot import is_aws
from localstack_snapshot.snapshots.transformer import KeyValueBasedTransformer

from localstack.aws.api.lambda_ import Runtime
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.testing.config import TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.aws import arns
from localstack.utils.common import now_utc, poll_condition, retry, short_uid
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO

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


@pytest.fixture
def logs_log_group(aws_client):
    name = f"test-log-group-{short_uid()}"
    aws_client.logs.create_log_group(logGroupName=name)
    yield name
    aws_client.logs.delete_log_group(logGroupName=name)


@pytest.fixture
def logs_log_stream(logs_log_group, aws_client):
    name = f"test-log-stream-{short_uid()}"
    aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=name)
    yield name
    aws_client.logs.delete_log_stream(logStreamName=name, logGroupName=logs_log_group)


class TestCloudWatchLogs:
    # TODO make creation and description atomic to avoid possible flake?
    @markers.aws.validated
    def test_create_and_delete_log_group(self, aws_client):
        test_name = f"test-log-group-{short_uid()}"
        log_groups_before = aws_client.logs.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])

        aws_client.logs.create_log_group(logGroupName=test_name)

        log_groups_between = aws_client.logs.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])
        assert poll_condition(
            lambda: len(log_groups_between) == len(log_groups_before) + 1, timeout=5.0, interval=0.5
        )

        aws_client.logs.delete_log_group(logGroupName=test_name)

        log_groups_after = aws_client.logs.describe_log_groups(
            logGroupNamePrefix="test-log-group-"
        ).get("logGroups", [])
        assert poll_condition(
            lambda: len(log_groups_after) == len(log_groups_between) - 1, timeout=5.0, interval=0.5
        )
        assert len(log_groups_after) == len(log_groups_before)

    @markers.aws.validated
    def test_list_tags_log_group(self, snapshot, aws_client):
        test_name = f"test-log-group-{short_uid()}"
        try:
            aws_client.logs.create_log_group(logGroupName=test_name, tags={"env": "testing1"})
            response = aws_client.logs.list_tags_log_group(logGroupName=test_name)
            snapshot.match("list_tags_after_create_log_group", response)

            # get group arn, to use the tag-resource api
            log_group_arn = aws_client.logs.describe_log_groups(logGroupNamePrefix=test_name)[
                "logGroups"
            ][0]["arn"].rstrip(":*")

            # add a tag - new api
            aws_client.logs.tag_resource(
                resourceArn=log_group_arn, tags={"test1": "val1", "test2": "val2"}
            )

            response = aws_client.logs.list_tags_log_group(logGroupName=test_name)
            response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)

            snapshot.match("list_tags_log_group_after_tag_resource", response)
            snapshot.match("list_tags_for_resource_after_tag_resource", response_2)
            # values should be the same
            assert response["tags"] == response_2["tags"]

            # add a tag - old api
            aws_client.logs.tag_log_group(logGroupName=test_name, tags={"test3": "val3"})

            response = aws_client.logs.list_tags_log_group(logGroupName=test_name)
            response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)

            snapshot.match("list_tags_log_group_after_tag_log_group", response)
            snapshot.match("list_tags_for_resource_after_tag_log_group", response_2)
            assert response["tags"] == response_2["tags"]

            # untag - use both apis
            aws_client.logs.untag_log_group(logGroupName=test_name, tags=["test3"])
            aws_client.logs.untag_resource(resourceArn=log_group_arn, tagKeys=["env", "test1"])

            response = aws_client.logs.list_tags_log_group(logGroupName=test_name)
            response_2 = aws_client.logs.list_tags_for_resource(resourceArn=log_group_arn)
            snapshot.match("list_tags_log_group_after_untag", response)
            snapshot.match("list_tags_for_resource_after_untag", response_2)

            assert response["tags"] == response_2["tags"]

        finally:
            # clean up
            aws_client.logs.delete_log_group(logGroupName=test_name)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # TODO 'describe-log-groups' returns different attributes on AWS when using
            #   'logGroupNamePattern' compared to 'logGroupNamePrefix' (for the same log group)
            #    seems like a weird issue on AWS side, we just exclude the paths here for this particular call
            "$..describe-log-groups-pattern.logGroups..metricFilterCount",
            "$..describe-log-groups-pattern.logGroups..storedBytes",
            "$..describe-log-groups-pattern.nextToken",
        ]
    )
    @markers.aws.validated
    def test_create_and_delete_log_stream(self, logs_log_group, aws_client, region_name, snapshot):
        snapshot.add_transformer(snapshot.transform.logs_api())
        test_name = f"test-log-stream-{short_uid()}"

        # filter for prefix/entire name here
        response = aws_client.logs.describe_log_groups(logGroupNamePrefix=logs_log_group)
        snapshot.match("describe-log-groups-prefix", response)

        # pattern for the short-uid
        # for some reason, this does not work immediately on AWS
        assert poll_condition(
            lambda: len(
                aws_client.logs.describe_log_groups(
                    logGroupNamePattern=logs_log_group.split("-")[-1]
                ).get("logGroups")
            )
            == 1,
            timeout=5.0,
            interval=0.5,
        )
        response = aws_client.logs.describe_log_groups(
            logGroupNamePattern=logs_log_group.split("-")[-1]
        )
        snapshot.match("describe-log-groups-pattern", response)

        # using prefix + pattern should raise error
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_log_groups(
                logGroupNamePattern=logs_log_group, logGroupNamePrefix=logs_log_group
            )
        snapshot.match("error-describe-logs-group", ctx.value.response)

        aws_client.logs.create_log_stream(logGroupName=logs_log_group, logStreamName=test_name)
        log_streams_between = aws_client.logs.describe_log_streams(logGroupName=logs_log_group).get(
            "logStreams", []
        )

        snapshot.match("logs_log_group", log_streams_between)

        # using log-group-name and log-group-identifier should raise exception
        with pytest.raises(Exception) as ctx:
            aws_client.logs.describe_log_streams(
                logGroupName=logs_log_group, logGroupIdentifier=logs_log_group
            )
        snapshot.match("error-describe-logs-streams", ctx.value.response)

        # log group identifier using the name of the log-group
        response = aws_client.logs.describe_log_streams(logGroupIdentifier=logs_log_group).get(
            "logStreams"
        )
        snapshot.match("log_group_identifier", response)
        # log group identifier using arn
        response = aws_client.logs.describe_log_streams(
            logGroupIdentifier=arns.log_group_arn(
                logs_log_group,
                account_id=aws_client.sts.get_caller_identity()["Account"],
                region_name=region_name,
            )
        ).get("logStreams")
        snapshot.match("log_group_identifier-arn", response)

        aws_client.logs.delete_log_stream(logGroupName=logs_log_group, logStreamName=test_name)

        log_streams_after = aws_client.logs.describe_log_streams(logGroupName=logs_log_group).get(
            "logStreams", []
        )
        assert len(log_streams_after) == 0

    @markers.aws.validated
    def test_put_events_multi_bytes_msg(self, logs_log_group, logs_log_stream, aws_client):
        body_msg = "🙀 - 参よ - 日本語"
        events = [{"timestamp": now_utc(millis=True), "message": body_msg}]
        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        def get_log_events():
            events = aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=logs_log_stream
            )["events"]
            assert events[0]["message"] == body_msg

        retry(
            get_log_events,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

    @markers.aws.validated
    def test_filter_log_events_response_header(self, logs_log_group, logs_log_stream, aws_client):
        events = [
            {"timestamp": now_utc(millis=True), "message": "log message 1"},
            {"timestamp": now_utc(millis=True), "message": "log message 2"},
        ]
        response = aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        response = aws_client.logs.filter_log_events(logGroupName=logs_log_group)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert (
            response["ResponseMetadata"]["HTTPHeaders"]["content-type"] == APPLICATION_AMZ_JSON_1_1
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Statement.Condition.StringEquals",
            "$..add_permission.ResponseMetadata.HTTPStatusCode",
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
        snapshot.add_transformer(snapshot.transform.lambda_api())
        # special replacements for this test case:
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
        # get account-id to set the correct policy
        account_id = aws_client.sts.get_caller_identity()["Account"]
        result = aws_client.lambda_.add_permission(
            FunctionName=test_lambda_name,
            StatementId=test_lambda_name,
            Principal=f"logs.{region_name}.amazonaws.com",
            Action="lambda:InvokeFunction",
            SourceArn=f"arn:aws:logs:{region_name}:{account_id}:log-group:{logs_log_group}:*",
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
            # we only are interested in events that contain "awslogs"
            filtered_events = []
            for e in events:
                if "awslogs" in e["message"]:
                    # the message will look like this:
                    # {"messageType":"DATA_MESSAGE","owner":"000000000000","logGroup":"log-group",
                    #  "logStream":"log-stream","subscriptionFilters":["test"],
                    #  "logEvents":[{"id":"7","timestamp":1679056073581,"message":"test"},
                    #               {"id":"8","timestamp":1679056073581,"message":"test 2"}]}
                    data = json.loads(e["message"])["awslogs"]["data"].encode("utf-8")
                    decoded_data = gzip.decompress(base64.b64decode(data)).decode("utf-8")
                    for log_event in json.loads(decoded_data)["logEvents"]:
                        filtered_events.append(log_event)
            assert len(filtered_events) == 2

            filtered_events.sort(key=lambda k: k.get("message"))
            snapshot.match("list_all_log_events", filtered_events)

        retry(check_invocation, retries=6, sleep=3.0)

    @markers.aws.validated
    def test_put_subscription_filter_firehose(
        self, logs_log_group, logs_log_stream, s3_bucket, create_iam_role_with_policy, aws_client
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
            # clean up
            aws_client.firehose.delete_delivery_stream(
                DeliveryStreamName=firehose_name, AllowForceDelete=True
            )

    @markers.aws.validated
    def test_put_subscription_filter_kinesis(
        self, logs_log_group, logs_log_stream, create_iam_role_with_policy, aws_client
    ):
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

            # wait for stream-status "ACTIVE"
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

            # for a weird reason the put_subscription_filter fails on AWS the first time,
            # even-though we check for ACTIVE state...
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
        # clean up
        finally:
            aws_client.kinesis.delete_stream(StreamName=kinesis_name, EnforceConsumerDeletion=True)
            aws_client.logs.delete_subscription_filter(
                logGroupName=logs_log_group, filterName=filter_name
            )

    @pytest.mark.skip("TODO: failing against community - filters are only in pro -> move test?")
    @markers.aws.validated
    def test_metric_filters(self, logs_log_group, logs_log_stream, aws_client):
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
        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=basic_filter_name,
            filterPattern=" ",
            metricTransformations=[basic_transforms],
        )
        aws_client.logs.put_metric_filter(
            logGroupName=logs_log_group,
            filterName=json_filter_name,
            filterPattern='{$.message = "test"}',
            metricTransformations=[json_transforms],
        )

        response = aws_client.logs.describe_metric_filters(
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
        aws_client.logs.put_log_events(
            logGroupName=logs_log_group, logStreamName=logs_log_stream, logEvents=events
        )

        # list metrics
        def list_metrics():
            res = aws_client.cloudwatch.list_metrics(Namespace=namespace_name)
            assert len(res["Metrics"]) == 2

        retry(
            list_metrics,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )

        # delete filters
        aws_client.logs.delete_metric_filter(
            logGroupName=logs_log_group, filterName=basic_filter_name
        )
        aws_client.logs.delete_metric_filter(
            logGroupName=logs_log_group, filterName=json_filter_name
        )

        response = aws_client.logs.describe_metric_filters(
            logGroupName=logs_log_group, filterNamePrefix="test-filter-"
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        filter_names = [_filter["filterName"] for _filter in response["metricFilters"]]
        assert basic_filter_name not in filter_names
        assert json_filter_name not in filter_names

    @markers.aws.needs_fixing
    def test_delivery_logs_for_sns(self, sns_create_topic, sns_subscription, aws_client):
        topic_name = f"test-logs-{short_uid()}"
        contact = "+10123456789"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=contact)

        message = "Good news everyone!"
        aws_client.sns.publish(Message=message, TopicArn=topic_arn)
        logs_group_name = topic_arn.replace("arn:aws:", "").replace(":", "/")

        def log_group_exists():
            # TODO on AWS the log group is not created, probably need iam role
            # see also https://repost.aws/knowledge-center/monitor-sns-texts-cloudwatch
            response = aws_client.logs.describe_log_streams(logGroupName=logs_group_name)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        retry(
            log_group_exists,
            retries=20 if is_aws() else 3,
            sleep=5 if is_aws() else 1,
            sleep_before=3 if is_aws() else 0,
        )
