"""Tests for EventBridge rules.
Tests for rule routing of events as well as rule creation and deletion.
"""

import json

import pytest
from botocore.exceptions import ClientError

from localstack.constants import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition
from tests.aws.services.events.conftest import assert_valid_event, sqs_collect_messages
from tests.aws.services.events.test_events import TEST_EVENT_BUS_NAME, TEST_EVENT_PATTERN


@markers.aws.validated
def test_put_rule(aws_client, snapshot, clean_up):
    rule_name = f"rule-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

    response = aws_client.events.put_rule(
        Name=rule_name, EventPattern=json.dumps(TEST_EVENT_PATTERN)
    )
    snapshot.match("put-rule", response)

    response = aws_client.events.list_rules(NamePrefix=rule_name)
    snapshot.match("list-rules", response)
    rules = response["Rules"]
    assert len(rules) == 1
    assert json.loads(rules[0]["EventPattern"]) == TEST_EVENT_PATTERN

    clean_up(rule_name=rule_name)


@markers.aws.validated
def test_rule_disable(aws_client, clean_up):
    rule_name = f"rule-{short_uid()}"
    aws_client.events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")

    response = aws_client.events.list_rules()
    assert response["Rules"][0]["State"] == "ENABLED"
    aws_client.events.disable_rule(Name=rule_name)
    response = aws_client.events.list_rules(NamePrefix=rule_name)
    assert response["Rules"][0]["State"] == "DISABLED"

    # clean up
    clean_up(rule_name=rule_name)


@markers.aws.validated
@pytest.mark.parametrize(
    "expression",
    [
        "rate(10 seconds)",
        "rate(10 years)",
        "rate(1 minutes)",
        "rate(1 hours)",
        "rate(1 days)",
        "rate(10 minute)",
        "rate(10 hour)",
        "rate(10 day)",
        "rate()",
        "rate(10)",
        "rate(10 minutess)",
        "rate(foo minutes)",
        "rate(0 minutes)",
        "rate(-10 minutes)",
        "rate(10 MINUTES)",
        "rate( 10 minutes )",
        " rate(10 minutes)",
    ],
)
def test_put_rule_invalid_rate_schedule_expression(expression, aws_client):
    with pytest.raises(ClientError) as e:
        aws_client.events.put_rule(Name=f"rule-{short_uid()}", ScheduleExpression=expression)

    assert e.value.response["Error"] == {
        "Code": "ValidationException",
        "Message": "Parameter ScheduleExpression is not valid.",
    }


@markers.aws.validated
def test_put_events_with_rule_anything_but_to_sqs(put_events_with_filter_to_sqs, snapshot):
    snapshot.add_transformer(
        [
            snapshot.transform.key_value("MD5OfBody"),
            snapshot.transform.key_value("ReceiptHandle"),
            snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
        ]
    )

    event_detail_match = {"command": "display-message", "payload": "baz"}
    event_detail_null = {"command": None, "payload": "baz"}
    event_detail_no_match = {"command": "no-message", "payload": "baz"}
    test_event_pattern_anything_but = {
        "source": ["core.update-account-command"],
        "detail-type": ["core.update-account-command"],
        "detail": {"command": [{"anything-but": ["no-message"]}]},
    }
    entries_match = [
        {
            "Source": test_event_pattern_anything_but["source"][0],
            "DetailType": test_event_pattern_anything_but["detail-type"][0],
            "Detail": json.dumps(event_detail_match),
        }
    ]
    entries_match_null = [
        {
            "Source": test_event_pattern_anything_but["source"][0],
            "DetailType": test_event_pattern_anything_but["detail-type"][0],
            "Detail": json.dumps(event_detail_null),
        }
    ]
    entries_no_match = [
        {
            "Source": test_event_pattern_anything_but["source"][0],
            "DetailType": test_event_pattern_anything_but["detail-type"][0],
            "Detail": json.dumps(event_detail_no_match),
        }
    ]

    entries_asserts = [
        (entries_match, True),
        (entries_match_null, True),
        (entries_no_match, False),
    ]

    messages = put_events_with_filter_to_sqs(
        pattern=test_event_pattern_anything_but,
        entries_asserts=entries_asserts,
    )
    snapshot.match("rule-anything-but", messages)


@markers.aws.validated
def test_put_events_with_rule_exists_true_to_sqs(put_events_with_filter_to_sqs, snapshot):
    """
    Exists matching True condition: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-exists-matching
    """
    snapshot.add_transformer(
        [
            snapshot.transform.key_value("MD5OfBody"),
            snapshot.transform.key_value("ReceiptHandle"),
            snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
        ]
    )

    event_detail_exists = {"key": "value", "payload": "baz"}
    event_detail_not_exists = {"no-key": "no-value", "payload": "baz"}
    event_patter_details = ["core.update-account-command"]
    test_event_pattern_exists = {
        "source": event_patter_details,
        "detail-type": event_patter_details,
        "detail": {"key": [{"exists": True}]},
    }
    entries_exists = [
        {
            "Source": test_event_pattern_exists["source"][0],
            "DetailType": test_event_pattern_exists["detail-type"][0],
            "Detail": json.dumps(event_detail_exists),
        }
    ]
    entries_not_exists = [
        {
            "Source": test_event_pattern_exists["source"][0],
            "DetailType": test_event_pattern_exists["detail-type"][0],
            "Detail": json.dumps(event_detail_not_exists),
        }
    ]
    entries_asserts = [
        (entries_exists, True),
        (entries_not_exists, False),
    ]

    messages = put_events_with_filter_to_sqs(
        pattern=test_event_pattern_exists,
        entries_asserts=entries_asserts,
    )
    snapshot.match("rule-exists-true", messages)


@markers.aws.validated
def test_put_events_with_rule_exists_false_to_sqs(put_events_with_filter_to_sqs, snapshot):
    """
    Exists matching False condition: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-exists-matching
    """
    snapshot.add_transformer(
        [
            snapshot.transform.key_value("MD5OfBody"),
            snapshot.transform.key_value("ReceiptHandle"),
            snapshot.transform.jsonpath("$..EventBusName", "event-bus-name"),
        ]
    )

    event_detail_exists = {"key": "value", "payload": "baz"}
    event_detail_not_exists = {"no-key": "no-value", "payload": "baz"}
    event_patter_details = ["core.update-account-command"]
    test_event_pattern_not_exists = {
        "source": event_patter_details,
        "detail-type": event_patter_details,
        "detail": {"key": [{"exists": False}]},
    }
    entries_exists = [
        {
            "Source": test_event_pattern_not_exists["source"][0],
            "DetailType": test_event_pattern_not_exists["detail-type"][0],
            "Detail": json.dumps(event_detail_exists),
        }
    ]
    entries_not_exists = [
        {
            "Source": test_event_pattern_not_exists["source"][0],
            "DetailType": test_event_pattern_not_exists["detail-type"][0],
            "Detail": json.dumps(event_detail_not_exists),
        }
    ]
    entries_asserts_exists_false = [
        (entries_exists, False),
        (entries_not_exists, True),
    ]

    messages_not_exists = put_events_with_filter_to_sqs(
        pattern=test_event_pattern_not_exists,
        entries_asserts=entries_asserts_exists_false,
    )
    snapshot.match("rule-exists-false", messages_not_exists)


@markers.aws.unknown
def test_put_event_with_content_base_rule_in_pattern(aws_client, clean_up):
    queue_name = f"queue-{short_uid()}"
    rule_name = f"rule-{short_uid()}"
    target_id = f"target-{short_uid()}"

    queue_url = aws_client.sqs.create_queue(QueueName=queue_name)["QueueUrl"]
    queue_arn = arns.sqs_queue_arn(queue_name, TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME)

    # EventBridge apparently converts some fields, for example: Source=>source, DetailType=>detail-type
    # but the actual pattern matching is case-sensitive by key!
    pattern = {
        "source": [{"exists": True}],
        "detail-type": [{"prefix": "core.app"}],
        "detail": {
            "description": ["this-is-event-details"],
            "amount": [200],
            "salary": [2000, 4000],
            "env": ["dev", "prod"],
            "user": ["user1", "user2", "user3"],
            "admins": ["skyli", {"prefix": "hey"}, {"prefix": "ad"}],
            "test1": [{"anything-but": 200}],
            "test2": [{"anything-but": "test2"}],
            "test3": [{"anything-but": ["test3", "test33"]}],
            "test4": [{"anything-but": {"prefix": "test4"}}],
            # TODO: unsupported in LocalStack
            # "ip": [{"cidr": "10.102.1.0/24"}],
            "num-test1": [{"numeric": ["<", 200]}],
            "num-test2": [{"numeric": ["<=", 200]}],
            "num-test3": [{"numeric": [">", 200]}],
            "num-test4": [{"numeric": [">=", 200]}],
            "num-test5": [{"numeric": [">=", 200, "<=", 500]}],
            "num-test6": [{"numeric": [">", 200, "<", 500]}],
            "num-test7": [{"numeric": [">=", 200, "<", 500]}],
        },
    }

    event = {
        "EventBusName": TEST_EVENT_BUS_NAME,
        "Source": "core.update-account-command",
        "DetailType": "core.app.backend",
        "Detail": json.dumps(
            {
                "description": "this-is-event-details",
                "amount": 200,
                "salary": 2000,
                "env": "prod",
                "user": "user3",
                "admins": "admin",
                "test1": 300,
                "test2": "test22",
                "test3": "test333",
                "test4": "this test4",
                "ip": "10.102.1.100",
                "num-test1": 100,
                "num-test2": 200,
                "num-test3": 300,
                "num-test4": 200,
                "num-test5": 500,
                "num-test6": 300,
                "num-test7": 300,
            }
        ),
    }

    aws_client.events.create_event_bus(Name=TEST_EVENT_BUS_NAME)
    aws_client.events.put_rule(
        Name=rule_name,
        EventBusName=TEST_EVENT_BUS_NAME,
        EventPattern=json.dumps(pattern),
    )

    aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=TEST_EVENT_BUS_NAME,
        Targets=[{"Id": target_id, "Arn": queue_arn, "InputPath": "$.detail"}],
    )
    aws_client.events.put_events(Entries=[event])

    messages = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)
    assert len(messages) == 1
    assert json.loads(messages[0].get("Body")) == json.loads(event["Detail"])
    event_details = json.loads(event["Detail"])
    event_details["admins"] = "no"
    event["Detail"] = json.dumps(event_details)

    aws_client.events.put_events(Entries=[event])

    messages = sqs_collect_messages(aws_client, queue_url, min_events=0, retries=1, wait_time=3)
    assert messages == []

    # clean up
    clean_up(
        bus_name=TEST_EVENT_BUS_NAME,
        rule_name=rule_name,
        target_ids=target_id,
        queue_url=queue_url,
    )


@markers.aws.validated
@pytest.mark.parametrize("schedule_expression", ["rate(1 minute)", "rate(1 day)", "rate(1 hour)"])
def test_create_rule_with_one_unit_in_singular_should_succeed(
    schedule_expression, aws_client, clean_up
):
    rule_name = f"rule-{short_uid()}"

    # rule should be creatable with given expression
    try:
        aws_client.events.put_rule(Name=rule_name, ScheduleExpression=schedule_expression)
    finally:
        clean_up(rule_name=rule_name)


@markers.aws.validated
@pytest.mark.xfail
def test_verify_rule_event_content(aws_client, clean_up):
    log_group_name = f"/aws/events/testLogGroup-{short_uid()}"
    rule_name = f"rule-{short_uid()}"
    target_id = f"testRuleId-{short_uid()}"

    aws_client.logs.create_log_group(logGroupName=log_group_name)
    log_groups = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    assert len(log_groups["logGroups"]) == 1
    log_group = log_groups["logGroups"][0]
    log_group_arn = log_group["arn"]

    aws_client.events.put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")
    aws_client.events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": log_group_arn}])

    def ensure_log_stream_exists():
        streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
        return len(streams["logStreams"]) == 1

    poll_condition(condition=ensure_log_stream_exists, timeout=65, interval=5)

    log_streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)
    log_stream_name = log_streams["logStreams"][0]["logStreamName"]

    log_content = aws_client.logs.get_log_events(
        logGroupName=log_group_name, logStreamName=log_stream_name
    )
    events = log_content["events"]
    assert len(events) == 1
    event = events[0]

    assert_valid_event(event["message"])

    clean_up(
        rule_name=rule_name,
        target_ids=target_id,
        log_group_name=log_group_name,
    )
