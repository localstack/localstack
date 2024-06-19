import json
import logging
from typing import Tuple

import pytest

from localstack.utils.functions import call_safe
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)


@pytest.fixture
def create_event_bus(aws_client):
    event_bus_names = []

    def _create_event_bus(**kwargs):
        response = aws_client.events.create_event_bus(**kwargs)
        event_bus_names.append(kwargs["Name"])
        return response

    yield _create_event_bus

    for event_bus_name in event_bus_names:
        try:
            response = aws_client.events.list_rules(EventBusName=event_bus_name)
            rules = [rule["Name"] for rule in response["Rules"]]

            # Delete all rules for the current event bus
            for rule in rules:
                try:
                    response = aws_client.events.list_targets_by_rule(
                        Rule=rule, EventBusName=event_bus_name
                    )
                    targets = [target["Id"] for target in response["Targets"]]

                    # Remove all targets for the current rule
                    if targets:
                        for target in targets:
                            aws_client.events.remove_targets(
                                Rule=rule, EventBusName=event_bus_name, Ids=[target]
                            )

                    aws_client.events.delete_rule(Name=rule, EventBusName=event_bus_name)
                except Exception as e:
                    LOG.warning(f"Failed to delete rule {rule}: {e}")

            aws_client.events.delete_event_bus(Name=event_bus_name)
        except Exception as e:
            LOG.warning(f"Failed to delete event bus {event_bus_name}: {e}")


@pytest.fixture
def put_rule(aws_client):
    rules = []

    def _put_rule(**kwargs):
        if "EventBusName" not in kwargs:
            kwargs["EventBusName"] = "default"
        response = aws_client.events.put_rule(**kwargs)
        rules.append((kwargs["Name"], kwargs["EventBusName"]))
        return response

    yield _put_rule

    for rule, event_bus_name in rules:
        try:
            response = aws_client.events.list_targets_by_rule(
                Rule=rule, EventBusName=event_bus_name
            )
            targets = [target["Id"] for target in response["Targets"]]

            # Remove all targets for the current rule
            if targets:
                for target in targets:
                    aws_client.events.remove_targets(
                        Rule=rule, EventBusName=event_bus_name, Ids=[target]
                    )

            aws_client.events.delete_rule(Name=rule, EventBusName=event_bus_name)
        except Exception as e:
            LOG.warning(f"Failed to delete rule {rule}: {e}")


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
        try:
            targets_response = aws_client.events.list_targets_by_rule(
                Rule=rule, EventBusName=event_bus_name
            )
            if targets := targets_response["Targets"]:
                targets_ids = [target["Id"] for target in targets]
                aws_client.events.remove_targets(
                    Rule=rule, EventBusName=event_bus_name, Ids=targets_ids
                )
            aws_client.events.delete_rule(Name=rule, EventBusName=event_bus_name)
        except Exception as e:
            LOG.debug("error cleaning up rule %s: %s", rule, e)


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


@pytest.fixture
def create_sqs_events_target(aws_client, sqs_get_queue_arn):
    queue_urls = []

    def _create_sqs_events_target(queue_name: str | None = None) -> tuple[str, str]:
        if not queue_name:
            queue_name = f"tests-queue-{short_uid()}"
        sqs_client = aws_client.sqs
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_urls.append(queue_url)
        queue_arn = sqs_get_queue_arn(queue_url)
        policy = {
            "Version": "2012-10-17",
            "Id": f"sqs-eventbridge-{short_uid()}",
            "Statement": [
                {
                    "Sid": f"SendMessage-{short_uid()}",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                }
            ],
        }
        sqs_client.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
        )
        return queue_url, queue_arn

    yield _create_sqs_events_target

    for queue_url in queue_urls:
        try:
            aws_client.sqs.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)


@pytest.fixture
def put_events_with_filter_to_sqs(aws_client, create_sqs_events_target, clean_up):
    event_bus_names = []
    rule_names = []
    target_ids = []

    def _put_events_with_filter_to_sqs(
        pattern: dict,
        entries_asserts: list[Tuple[list[dict], bool]],
        input_path: str = None,
        input_transformer: dict[dict, str] = None,
    ):
        rule_name = f"test-rule-{short_uid()}"
        target_id = f"test-target-{short_uid()}"
        bus_name = f"test-bus-{short_uid()}"

        queue_url, queue_arn = create_sqs_events_target()

        events_client = aws_client.events
        events_client.create_event_bus(Name=bus_name)
        event_bus_names.append(bus_name)

        events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(pattern),
        )
        rule_names.append(rule_name)
        kwargs = {"InputPath": input_path} if input_path else {}
        if input_transformer:
            kwargs["InputTransformer"] = input_transformer
        response = events_client.put_targets(
            Rule=rule_name,
            EventBusName=bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, **kwargs}],
        )
        target_ids.append(target_id)

        assert response["FailedEntryCount"] == 0
        assert response["FailedEntries"] == []

        messages = []
        for entry_asserts in entries_asserts:
            entries = entry_asserts[0]
            for entry in entries:
                entry["EventBusName"] = bus_name
            message = _put_entries_assert_results_sqs(
                events_client,
                aws_client.sqs,
                queue_url,
                entries=entries,
                should_match=entry_asserts[1],
            )
            if message is not None:
                messages.extend(message)

        return messages

    yield _put_events_with_filter_to_sqs

    for event_bus_name, rule_name, target_id in zip(event_bus_names, rule_names, target_ids):
        clean_up(
            bus_name=event_bus_name,
            rule_name=rule_name,
            target_ids=target_id,
        )


def _put_entries_assert_results_sqs(
    events_client, sqs_client, queue_url: str, entries: list[dict], should_match: bool
):
    """
    Put events to the event bus, receives the messages resulting from the event in the sqs queue and deletes them out of the queue.
    If should_match is True, the content of the messages is asserted to be the same as the events put to the event bus.

    :param events_client: boto3.client("events")
    :param sqs_client: boto3.client("sqs")
    :param queue_url: URL of the sqs queue
    :param entries: List of entries to put to the event bus, each entry must
                    be a dict that contains the keys: "Source", "DetailType", "Detail"
    :param should_match:

    :return: Messages from the queue if should_match is True, otherwise None
    """
    response = events_client.put_events(Entries=entries)
    assert not response.get("FailedEntryCount")

    def get_message(queue_url):
        resp = sqs_client.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=5, MaxNumberOfMessages=1
        )
        messages = resp.get("Messages")
        if messages:
            for message in messages:
                receipt_handle = message["ReceiptHandle"]
                sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        if should_match:
            assert len(messages) == 1
        return messages

    messages = retry(get_message, retries=5, queue_url=queue_url)

    if should_match:
        actual_event = json.loads(messages[0]["Body"])
        if isinstance(actual_event, dict) and "detail" in actual_event:
            assert_valid_event(actual_event)
        return messages
    else:
        assert not messages
        return None


def assert_valid_event(event):
    expected_fields = (
        "version",
        "id",
        "detail-type",
        "source",
        "account",
        "time",
        "region",
        "resources",
        "detail",
    )
    for field in expected_fields:
        assert field in event


@pytest.fixture
def logs_create_log_group(aws_client):
    log_group_names = []

    def _create_log_group(name: str = None) -> str:
        if not name:
            name = f"test-log-group-{short_uid()}"

        aws_client.logs.create_log_group(logGroupName=name)
        log_group_names.append(name)

        return name

    yield _create_log_group

    for name in log_group_names:
        try:
            aws_client.logs.delete_log_group(logGroupName=name)
        except Exception as e:
            LOG.debug("error cleaning up log group %s: %s", name, e)


@pytest.fixture
def add_resource_policy_logs_events_access(aws_client):
    policies = []

    def _add_resource_policy_logs_events_access(log_group_arn: str):
        policy_name = f"test-policy-{short_uid()}"

        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowPutEvents",
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                    "Resource": log_group_arn,
                },
            ],
        }
        policy = aws_client.logs.put_resource_policy(
            policyName=policy_name,
            policyDocument=json.dumps(policy_document),
        )

        policies.append(policy_name)

        return policy

    yield _add_resource_policy_logs_events_access

    for policy_name in policies:
        aws_client.logs.delete_resource_policy(policyName=policy_name)


@pytest.fixture
def events_create_connection(aws_client):
    connections = []

    def _create_connection(**kwargs):
        response = aws_client.events.create_connection(**kwargs)
        connections.append(kwargs["Name"])
        return response

    yield _create_connection

    for connection in connections:
        try:
            aws_client.events.delete_connection(Name=connection)
        except Exception as e:
            LOG.warning(f"Failed to delete connection {connection}: {e}")
