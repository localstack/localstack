"""Tests for integrations between AWS EventBridge and other AWS services."""

import json
from datetime import datetime

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns, resources
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from tests.aws.services.events.helper_functions import (
    assert_valid_event,
    is_v2_provider,
    sqs_collect_messages,
)
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON_ECHO


@markers.aws.validated
def test_put_events_with_target_sqs(put_events_with_filter_to_sqs, snapshot):
    entries = [
        {
            "Source": TEST_EVENT_PATTERN["source"][0],
            "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
            "Detail": json.dumps(EVENT_DETAIL),
        }
    ]
    message = put_events_with_filter_to_sqs(
        pattern=TEST_EVENT_PATTERN,
        entries_asserts=[(entries, True)],
    )
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
            snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
        ],
    )
    snapshot.match("message", message)


@markers.aws.unknown
@pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
def test_put_events_with_target_sqs_new_region(aws_client_factory):
    events_client = aws_client_factory(region_name="eu-west-1").events
    queue_name = "queue-{}".format(short_uid())
    rule_name = "rule-{}".format(short_uid())
    target_id = "target-{}".format(short_uid())
    bus_name = "bus-{}".format(short_uid())

    sqs_client = aws_client_factory(region_name="eu-west-1").sqs
    sqs_client.create_queue(QueueName=queue_name)
    queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

    events_client.create_event_bus(Name=bus_name)

    events_client.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )

    events_client.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": queue_arn}],
    )

    response = events_client.put_events(
        Entries=[
            {
                "Source": "com.mycompany.myapp",
                "Detail": '{ "key1": "value1", "key": "value2" }',
                "Resources": [],
                "DetailType": "myDetailType",
            }
        ]
    )
    assert "Entries" in response
    assert len(response.get("Entries")) == 1
    assert "EventId" in response.get("Entries")[0]


@markers.aws.validated
@pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
def test_put_events_with_target_sqs_event_detail_match(put_events_with_filter_to_sqs, snapshot):
    entries1 = [
        {
            "Source": TEST_EVENT_PATTERN["source"][0],
            "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
            "Detail": json.dumps({"EventType": "1"}),
        }
    ]
    entries2 = [
        {
            "Source": TEST_EVENT_PATTERN["source"][0],
            "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
            "Detail": json.dumps({"EventType": "2"}),
        }
    ]
    entries_asserts = [(entries1, True), (entries2, False)]
    messages = put_events_with_filter_to_sqs(
        pattern={"detail": {"EventType": ["0", "1"]}},
        entries_asserts=entries_asserts,
        input_path="$.detail",
    )

    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
            snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
        ],
    )
    snapshot.match("messages", messages)


# TODO: further unify/parameterize the tests for the different target types below


@markers.aws.needs_fixing
@pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
def test_put_events_with_target_sns(
    monkeypatch,
    sns_subscription,
    aws_client,
    clean_up,
    strategy,
):
    monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

    queue_name = "test-%s" % short_uid()
    rule_name = "rule-{}".format(short_uid())
    target_id = "target-{}".format(short_uid())
    bus_name = "bus-{}".format(short_uid())

    topic_name = "topic-{}".format(short_uid())
    topic_arn = aws_client.sns.create_topic(Name=topic_name)["TopicArn"]

    queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

    sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

    aws_client.events.create_event_bus(Name=bus_name)
    aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )
    rs = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": topic_arn}],
    )

    assert "FailedEntryCount" in rs
    assert "FailedEntries" in rs
    assert rs["FailedEntryCount"] == 0
    assert rs["FailedEntries"] == []

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
    )

    messages = sqs_collect_messages(aws_client, queue_url, expected_events_count=1, retries=3)
    assert len(messages) == 1

    actual_event = json.loads(messages[0]["Body"]).get("Message")
    assert_valid_event(actual_event)
    assert json.loads(actual_event).get("detail") == EVENT_DETAIL

    # clean up
    aws_client.sns.delete_topic(TopicArn=topic_arn)
    clean_up(
        bus_name=bus_name,
        rule_name=rule_name,
        target_ids=target_id,
        queue_url=queue_url,
    )


@markers.aws.needs_fixing
def test_put_events_with_target_lambda(create_lambda_function, cleanups, aws_client, clean_up):
    rule_name = f"rule-{short_uid()}"
    function_name = f"lambda-func-{short_uid()}"
    target_id = f"target-{short_uid()}"
    bus_name = f"bus-{short_uid()}"

    # clean up
    cleanups.append(lambda: aws_client.lambda_.delete_function(FunctionName=function_name))
    cleanups.append(lambda: clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id))

    rs = create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    func_arn = rs["CreateFunctionResponse"]["FunctionArn"]

    aws_client.events.create_event_bus(Name=bus_name)
    aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )
    rs = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": func_arn}],
    )

    assert "FailedEntryCount" in rs
    assert "FailedEntries" in rs
    assert rs["FailedEntryCount"] == 0
    assert rs["FailedEntries"] == []

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
    )

    # Get lambda's log events
    events = retry(
        check_expected_lambda_log_events_length,
        retries=3,
        sleep=1,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )
    actual_event = events[0]
    assert_valid_event(actual_event)
    assert actual_event["detail"] == EVENT_DETAIL


@markers.aws.validated
def test_put_events_with_target_lambda_list_entry(
    create_lambda_function, cleanups, aws_client, clean_up, snapshot
):
    rule_name = f"rule-{short_uid()}"
    function_name = f"lambda-func-{short_uid()}"
    target_id = f"target-{short_uid()}"
    bus_name = f"bus-{short_uid()}"

    # clean up
    cleanups.append(lambda: clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id))

    create_lambda_response = create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )

    func_arn = create_lambda_response["CreateFunctionResponse"]["FunctionArn"]

    event_pattern = {"detail": {"payload": {"automations": {"id": [{"exists": True}]}}}}

    aws_client.events.create_event_bus(Name=bus_name)
    put_rule_response = aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(event_pattern),
    )
    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"{rule_name}-Event",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=put_rule_response["RuleArn"],
    )
    put_target_response = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": func_arn}],
    )

    assert "FailedEntryCount" in put_target_response
    assert "FailedEntries" in put_target_response
    assert put_target_response["FailedEntryCount"] == 0
    assert put_target_response["FailedEntries"] == []

    event_detail = {
        "payload": {
            "userId": 10,
            "businessId": 3,
            "channelId": 6,
            "card": {"foo": "bar"},
            "targetEntity": True,
            "entityAuditTrailEvent": {"foo": "bar"},
            "automations": [
                {
                    "id": "123",
                    "actions": [
                        {
                            "id": "321",
                            "type": "SEND_NOTIFICATION",
                            "settings": {
                                "message": "",
                                "recipientEmails": [],
                                "subject": "",
                                "type": "SEND_NOTIFICATION",
                            },
                        }
                    ],
                }
            ],
        }
    }
    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(event_detail),
            }
        ]
    )

    # Get lambda's log events
    events = retry(
        check_expected_lambda_log_events_length,
        retries=15,
        sleep=1,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )
    snapshot.match("events", events)


@markers.aws.validated
def test_put_events_with_target_lambda_list_entries_partial_match(
    create_lambda_function, cleanups, aws_client, clean_up, snapshot
):
    rule_name = f"rule-{short_uid()}"
    function_name = f"lambda-func-{short_uid()}"
    target_id = f"target-{short_uid()}"
    bus_name = f"bus-{short_uid()}"

    # clean up
    cleanups.append(lambda: clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id))

    rs = create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_12,
    )

    func_arn = rs["CreateFunctionResponse"]["FunctionArn"]

    event_pattern = {"detail": {"payload": {"automations": {"id": [{"exists": True}]}}}}

    aws_client.events.create_event_bus(Name=bus_name)
    rs = aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(event_pattern),
    )
    aws_client.lambda_.add_permission(
        FunctionName=function_name,
        StatementId=f"{rule_name}-Event",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rs["RuleArn"],
    )
    rs = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": func_arn}],
    )

    assert "FailedEntryCount" in rs
    assert "FailedEntries" in rs
    assert rs["FailedEntryCount"] == 0
    assert rs["FailedEntries"] == []

    event_detail_partial_match = {
        "payload": {
            "userId": 10,
            "businessId": 3,
            "channelId": 6,
            "card": {"foo": "bar"},
            "targetEntity": True,
            "entityAuditTrailEvent": {"foo": "bar"},
            "automations": [
                {"foo": "bar"},
                {
                    "id": "123",
                    "actions": [
                        {
                            "id": "321",
                            "type": "SEND_NOTIFICATION",
                            "settings": {
                                "message": "",
                                "recipientEmails": [],
                                "subject": "",
                                "type": "SEND_NOTIFICATION",
                            },
                        }
                    ],
                },
                {"bar": "foo"},
            ],
        }
    }
    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(event_detail_partial_match),
            },
        ]
    )

    # Get lambda's log events
    events = retry(
        check_expected_lambda_log_events_length,
        retries=15,
        sleep=1,
        function_name=function_name,
        expected_length=1,
        logs_client=aws_client.logs,
    )
    snapshot.match("events", events)


@markers.aws.validated
@pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
def test_should_ignore_schedules_for_put_event(create_lambda_function, cleanups, aws_client):
    """Regression test for https://github.com/localstack/localstack/issues/7847"""
    fn_name = f"test-event-fn-{short_uid()}"
    create_lambda_function(
        func_name=fn_name,
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        runtime=Runtime.python3_9,
        client=aws_client.lambda_,
    )

    aws_client.lambda_.add_permission(
        FunctionName=fn_name,
        StatementId="AllowFnInvokeStatement",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
    )

    fn_arn = aws_client.lambda_.get_function(FunctionName=fn_name)["Configuration"]["FunctionArn"]
    aws_client.events.put_rule(
        Name="ScheduledLambda", ScheduleExpression="rate(1 minute)"
    )  # every minute, can't go lower than that
    cleanups.append(lambda: aws_client.events.delete_rule(Name="ScheduledLambda"))
    aws_client.events.put_targets(
        Rule="ScheduledLambda", Targets=[{"Id": "calllambda1", "Arn": fn_arn}]
    )
    cleanups.append(
        lambda: aws_client.events.remove_targets(Rule="ScheduledLambda", Ids=["calllambda1"])
    )

    aws_client.events.put_events(
        Entries=[
            {
                "Source": "MySource",
                "DetailType": "CustomType",
                "Detail": json.dumps({"message": "manually invoked"}),
            }
        ]
    )

    def check_invocation():
        events_after = aws_client.logs.filter_log_events(logGroupName=f"/aws/lambda/{fn_name}")
        # the custom sent event should NOT trigger the lambda (!)
        assert len([e for e in events_after["events"] if "START" in e["message"]]) >= 1
        assert len([e for e in events_after["events"] if "manually invoked" in e["message"]]) == 0

    retry(check_invocation, sleep=5, retries=15)


@markers.aws.needs_fixing
def test_put_events_with_target_firehose(aws_client, clean_up):
    s3_bucket = "s3-{}".format(short_uid())
    s3_prefix = "testeventdata"
    stream_name = "firehose-{}".format(short_uid())
    rule_name = "rule-{}".format(short_uid())
    target_id = "target-{}".format(short_uid())
    bus_name = "bus-{}".format(short_uid())

    # create firehose target bucket
    resources.get_or_create_bucket(s3_bucket, s3_client=aws_client.s3)

    # create firehose delivery stream to s3
    stream = aws_client.firehose.create_delivery_stream(
        DeliveryStreamName=stream_name,
        S3DestinationConfiguration={
            "RoleARN": arns.iam_resource_arn("firehose", TEST_AWS_ACCOUNT_ID),
            "BucketARN": arns.s3_bucket_arn(s3_bucket),
            "Prefix": s3_prefix,
        },
    )
    stream_arn = stream["DeliveryStreamARN"]

    aws_client.events.create_event_bus(Name=bus_name)
    aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )
    rs = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[{"Id": target_id, "Arn": stream_arn}],
    )

    assert "FailedEntryCount" in rs
    assert "FailedEntries" in rs
    assert rs["FailedEntryCount"] == 0
    assert rs["FailedEntries"] == []

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
    )

    # run tests
    bucket_contents = aws_client.s3.list_objects(Bucket=s3_bucket)["Contents"]
    assert len(bucket_contents) == 1
    key = bucket_contents[0]["Key"]
    s3_object = aws_client.s3.get_object(Bucket=s3_bucket, Key=key)
    actual_event = json.loads(s3_object["Body"].read().decode())
    assert_valid_event(actual_event)
    assert actual_event["detail"] == EVENT_DETAIL

    # clean up
    aws_client.firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    # empty and delete bucket
    aws_client.s3.delete_object(Bucket=s3_bucket, Key=key)
    aws_client.s3.delete_bucket(Bucket=s3_bucket)
    clean_up(bus_name=bus_name, rule_name=rule_name, target_ids=target_id)


@markers.aws.unknown
@pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
def test_put_events_with_target_kinesis(aws_client):
    rule_name = "rule-{}".format(short_uid())
    target_id = "target-{}".format(short_uid())
    bus_name = "bus-{}".format(short_uid())
    stream_name = "stream-{}".format(short_uid())
    stream_arn = arns.kinesis_stream_arn(stream_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

    aws_client.kinesis.create_stream(StreamName=stream_name, ShardCount=1)

    aws_client.events.create_event_bus(Name=bus_name)

    aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )

    put_response = aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=bus_name,
        Targets=[
            {
                "Id": target_id,
                "Arn": stream_arn,
                "KinesisParameters": {"PartitionKeyPath": "$.detail-type"},
            }
        ],
    )

    assert "FailedEntryCount" in put_response
    assert "FailedEntries" in put_response
    assert put_response["FailedEntryCount"] == 0
    assert put_response["FailedEntries"] == []

    def check_stream_status():
        _stream = aws_client.kinesis.describe_stream(StreamName=stream_name)
        assert _stream["StreamDescription"]["StreamStatus"] == "ACTIVE"

    # wait until stream becomes available
    retry(check_stream_status, retries=7, sleep=0.8)

    aws_client.events.put_events(
        Entries=[
            {
                "EventBusName": bus_name,
                "Source": TEST_EVENT_PATTERN["source"][0],
                "DetailType": TEST_EVENT_PATTERN["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
            }
        ]
    )

    stream = aws_client.kinesis.describe_stream(StreamName=stream_name)
    shard_id = stream["StreamDescription"]["Shards"][0]["ShardId"]
    shard_iterator = aws_client.kinesis.get_shard_iterator(
        StreamName=stream_name,
        ShardId=shard_id,
        ShardIteratorType="AT_TIMESTAMP",
        Timestamp=datetime(2020, 1, 1),
    )["ShardIterator"]

    record = aws_client.kinesis.get_records(ShardIterator=shard_iterator)["Records"][0]

    partition_key = record["PartitionKey"]
    data = json.loads(record["Data"].decode())

    assert partition_key == TEST_EVENT_PATTERN["detail-type"][0]
    assert data["detail"] == EVENT_DETAIL
    assert_valid_event(data)


@markers.aws.needs_fixing  # TODO: Reason add permission and correct policies
@pytest.mark.parametrize("strategy", ["standard", "domain", "path"])
def test_trigger_event_on_ssm_change(monkeypatch, aws_client, clean_up, strategy):
    monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

    rule_name = "rule-{}".format(short_uid())
    target_id = "target-{}".format(short_uid())

    # create queue
    queue_name = "queue-{}".format(short_uid())
    queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

    # put rule listening on SSM changes
    ssm_prefix = "/test/local/"
    aws_client.events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "detail": {
                    "name": [{"prefix": ssm_prefix}],
                    "operation": [
                        "Create",
                        "Update",
                        "Delete",
                        "LabelParameterVersion",
                    ],
                },
                "detail-type": ["Parameter Store Change"],
                "source": ["aws.ssm"],
            }
        ),
        State="ENABLED",
        Description="Trigger on SSM parameter changes",
    )

    # put target
    aws_client.events.put_targets(
        Rule=rule_name,
        Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
    )

    param_suffix = short_uid()

    # change SSM param to trigger event
    aws_client.ssm.put_parameter(
        Name=f"{ssm_prefix}/test-{param_suffix}", Value="value1", Type="String"
    )

    def assert_message():
        resp = aws_client.sqs.receive_message(QueueUrl=queue_url)
        result = resp.get("Messages")
        body = json.loads(result[0]["Body"])
        assert body == {
            "name": f"/test/local/test-{param_suffix}",
            "operation": "Create",
        }

    # assert that message has been received
    retry(assert_message, retries=7, sleep=0.3)

    # clean up
    clean_up(rule_name=rule_name, target_ids=target_id)
