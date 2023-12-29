import json

import pytest

from localstack.utils.strings import short_uid


@pytest.fixture
def events_allow_event_rule_to_sqs_queue(aws_client):
    def _allow_event_rule(sqs_queue_url, sqs_queue_arn, event_rule_arn) -> None:
        # allow event rule to write to sqs queue
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue_url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "AllowEventsToQueue",
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": sqs_queue_arn,
                                "Condition": {"ArnEquals": {"aws:SourceArn": event_rule_arn}},
                            }
                        ]
                    }
                )
            },
        )

    return _allow_event_rule


@pytest.fixture
def events_put_rule(aws_client):
    rules = []

    def _factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"rule-{short_uid()}"

        resp = aws_client.events.put_rule(**kwargs)
        rules.append((kwargs["Name"], kwargs.get("EventBusName", "default")))
        return resp

    yield _factory

    for rule, event_bus_name in rules:
        targets_response = aws_client.events.list_targets_by_rule(
            Rule=rule, EventBusName=event_bus_name
        )
        if targets := targets_response["Targets"]:
            targets_ids = [target["Id"] for target in targets]
            aws_client.events.remove_targets(
                Rule=rule, EventBusName=event_bus_name, Ids=targets_ids
            )
        aws_client.events.delete_rule(Name=rule, EventBusName=event_bus_name)


@pytest.fixture
def events_create_event_bus(aws_client):
    event_buses = []

    def _factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"event-bus-{short_uid()}"
        resp = aws_client.events.create_event_bus(**kwargs)
        event_buses.append(kwargs["Name"])
        return resp

    yield _factory

    for event_bus in event_buses:
        aws_client.events.delete_event_bus(Name=event_bus)
