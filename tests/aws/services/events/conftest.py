import json

import pytest

from localstack.utils.functions import call_safe
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


@pytest.fixture
def clean_up(aws_client):
    def _clean_up(
        bus_name=None,
        rule_name=None,
        target_ids=None,
        queue_url=None,
        log_group_name=None,
    ):
        events_client = aws_client.events
        kwargs = {"EventBusName": bus_name} if bus_name else {}
        if target_ids:
            target_ids = target_ids if isinstance(target_ids, list) else [target_ids]
            call_safe(
                events_client.remove_targets,
                kwargs=dict(Rule=rule_name, Ids=target_ids, Force=True, **kwargs),
            )
        if rule_name:
            call_safe(events_client.delete_rule, kwargs=dict(Name=rule_name, Force=True, **kwargs))
        if bus_name:
            call_safe(events_client.delete_event_bus, kwargs=dict(Name=bus_name))
        if queue_url:
            sqs_client = aws_client.sqs
            call_safe(sqs_client.delete_queue, kwargs=dict(QueueUrl=queue_url))
        if log_group_name:
            logs_client = aws_client.logs

            def _delete_log_group():
                log_streams = logs_client.describe_log_streams(logGroupName=log_group_name)
                for log_stream in log_streams["logStreams"]:
                    logs_client.delete_log_stream(
                        logGroupName=log_group_name, logStreamName=log_stream["logStreamName"]
                    )
                logs_client.delete_log_group(logGroupName=log_group_name)

            call_safe(_delete_log_group)

    yield _clean_up
