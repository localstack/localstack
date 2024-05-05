import json
import logging

import pytest

from localstack.testing.aws.eventbus_utils import (
    allow_event_rule_to_sqs_queue,
    trigger_scheduled_rule,
)
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import TransformerUtility
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.events.helper_functions import is_v2_provider

LOG = logging.getLogger(__name__)


@markers.aws.validated
@pytest.mark.skipif(is_v2_provider(), reason="V2 provider does not support this feature yet")
def test_scheduled_rule_sqs(
    sqs_create_queue,
    events_put_rule,
    aws_client,
    snapshot,
):
    schedule_expression = "rate(1 minute)"
    rule_name = f"rule-{short_uid()}"

    snapshot.add_transformer(TransformerUtility.sqs_api())
    # the generated message has a date, so the MD5 will be different every time
    snapshot.add_transformer(snapshot.transform.key_value("MD5OfBody"))
    snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

    queue_url = sqs_create_queue()
    queue_arn = aws_client.sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]

    rule_arn = events_put_rule(Name=rule_name, ScheduleExpression=schedule_expression)["RuleArn"]

    allow_event_rule_to_sqs_queue(aws_client, queue_url, queue_arn, rule_arn)
    aws_client.events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "1", "Arn": queue_arn},
            {"Id": "2", "Arn": queue_arn, "Input": json.dumps({"custom-value": "somecustominput"})},
        ],
    )

    messages = []

    trigger_scheduled_rule(rule_arn)

    def _collect_sqs_messages():
        _response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=20, MaxNumberOfMessages=10
        )
        messages.extend(_response.get("Messages", []))

        if len(messages) < 2:
            raise AssertionError(f"Expected at least 2 messages in {messages}")

    retry(_collect_sqs_messages, retries=6, sleep=0.1)

    # hacky sorting of messages
    messages.sort(key=lambda m: 1 if "custom-value" in m["Body"] else 0)

    snapshot.match("sqs-messages", messages)
