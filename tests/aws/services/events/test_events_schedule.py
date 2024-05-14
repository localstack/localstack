import json
import time
from datetime import timedelta, timezone

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.conftest import sqs_collect_messages
from tests.aws.services.events.helper_functions import (
    events_time_string_to_timestamp,
    get_cron_expression,
)


class TestScheduleRate:
    @markers.aws.validated
    def test_put_rule_with_schedule_rate(self, events_put_rule, aws_client, snapshot):
        rule_name = f"rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        response = events_put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")
        snapshot.match("put-rule", response)

        response = aws_client.events.list_rules(NamePrefix=rule_name)
        snapshot.match("list-rules", response)

    @markers.aws.validated
    def tests_put_rule_with_schedule_custom_event_bus(
        self,
        events_create_event_bus,
        aws_client,
        snapshot,
    ):
        bus_name = f"test-bus-{short_uid()}"
        events_create_event_bus(Name=bus_name)

        rule_name = f"test-rule-{short_uid()}"
        with pytest.raises(ClientError) as e:
            aws_client.events.put_rule(
                Name=rule_name, EventBusName=bus_name, ScheduleExpression="rate(1 minute)"
            )
        snapshot.match("put-rule-with-custom-event-bus-error", e)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "schedule_expression",
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
    def test_put_rule_with_invalid_schedule_rate(self, schedule_expression, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.events.put_rule(
                Name=f"rule-{short_uid()}", ScheduleExpression=schedule_expression
            )

        assert e.value.response["Error"] == {
            "Code": "ValidationException",
            "Message": "Parameter ScheduleExpression is not valid.",
        }

    @markers.aws.validated
    def tests_schedule_rate_target_sqs(
        self,
        create_sqs_events_target,
        events_put_rule,
        aws_client,
        snapshot,
    ):
        queue_url, queue_arn = create_sqs_events_target()

        bus_name = "default"
        rule_name = f"test-rule-{short_uid()}"
        events_put_rule(Name=rule_name, EventBusName=bus_name, ScheduleExpression="rate(1 minute)")

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn},
            ],
        )  # cleanup is handled by rule fixture

        response = aws_client.events.list_targets_by_rule(Rule=rule_name)
        snapshot.match("list-targets", response)

        time.sleep(60)
        messages_first = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("messages-first", messages_first)

        time.sleep(60)
        messages_second = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)
        snapshot.match("messages-second", messages_second)

        # check if the messages are 60 seconds apart
        time_messages_first = events_time_string_to_timestamp(
            json.loads(messages_first[0]["Body"])["time"]
        )
        time_messages_second = events_time_string_to_timestamp(
            json.loads(messages_second[0]["Body"])["time"]
        )
        time_delta = time_messages_second - time_messages_first
        assert time_delta == timedelta(seconds=60)

    @markers.aws.validated
    def tests_schedule_rate_custom_input_target_sqs(
        self, create_sqs_events_target, events_put_rule, aws_client, snapshot
    ):
        queue_url, queue_arn = create_sqs_events_target()

        bus_name = "default"
        rule_name = f"test-rule-{short_uid()}"
        events_put_rule(Name=rule_name, EventBusName=bus_name, ScheduleExpression="rate(1 minute)")

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {
                    "Id": target_id,
                    "Arn": queue_arn,
                    "Input": json.dumps({"custom-value": "somecustominput"}),
                },
            ],
        )  # cleanup is handled by rule fixture

        response = aws_client.events.list_targets_by_rule(Rule=rule_name)
        snapshot.match("list-targets", response)

        time.sleep(60)
        messages_first = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=3)

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("messages", messages_first)


class TestScheduleCron:
    @markers.aws.validated
    @pytest.mark.parametrize(
        "schedule_cron",
        [
            "cron(0 10 * * ? *)",  # Run at 10:00 am every day
            "cron(15 12 * * ? *)",  # Run at 12:15 pm every day
            "cron(0 18 ? * MON-FRI *)",  # Run at 6:00 pm every Monday through Friday
            "cron(0 8 1 * ? *)",  # Run at 8:00 am on the 1st day of every month
            "cron(0/15 * * * ? *)",  # Run every 15 minutes
            "cron(0/10 * ? * MON-FRI *)",  # Run every 10 minutes Monday through Friday
            "cron(0/5 8-17 ? * MON-FRI *)",  # Run every 5 minutes Monday through Friday between 8:00 am and 5:55 pm
            "cron(0/30 20-23 ? * MON-FRI *)",  # Run every 30 minutes between 8:00 pm and 11:59 pm Monday through Friday
            "cron(0/30 0-2 ? * MON-FRI *)",  # Run every 30 minutes between 12:00 am and 2:00 am Monday through Friday
        ],
    )
    def tests_put_rule_with_schedule_cron(
        self, schedule_cron, events_put_rule, aws_client, snapshot
    ):
        rule_name = f"rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        response = events_put_rule(Name=rule_name, ScheduleExpression=schedule_cron)
        snapshot.match("put-rule", response)

        response = aws_client.events.list_rules(NamePrefix=rule_name)
        snapshot.match("list-rules", response)

    @markers.aws.validated
    def test_schedule_cron_target_sqs(
        self,
        create_sqs_events_target,
        events_put_rule,
        aws_client,
        snapshot,
    ):
        queue_url, queue_arn = create_sqs_events_target()

        schedule_cron, target_datetime = get_cron_expression(
            1
        )  # only next full minut might be to fast for setup must be UTC time zone

        bus_name = "default"
        rule_name = f"test-rule-{short_uid()}"
        events_put_rule(Name=rule_name, EventBusName=bus_name, ScheduleExpression=schedule_cron)

        target_id = f"target-{short_uid()}"
        aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[
                {"Id": target_id, "Arn": queue_arn},
            ],
        )

        time.sleep(120)  # required to wait for time delta 1 minute starting from next full minute
        messages = sqs_collect_messages(aws_client, queue_url, min_events=1, retries=5)

        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("MD5OfBody"),
                snapshot.transform.key_value("ReceiptHandle"),
            ]
        )
        snapshot.match("message", messages)

        # check if message was delivered at the correct time
        time_message = events_time_string_to_timestamp(
            json.loads(messages[0]["Body"])["time"]
        ).replace(tzinfo=timezone.utc)
        assert time_message == target_datetime
