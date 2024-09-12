import json
import logging
from typing import Tuple

import pytest

from localstack.utils.aws.arns import get_partition
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.events.helper_functions import put_entries_assert_results_sqs

LOG = logging.getLogger(__name__)


@pytest.fixture
def events_create_event_bus(aws_client, region_name, account_id):
    event_bus_names = []

    def _create_event_bus(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"test-event-bus-{short_uid()}"

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
                    LOG.warning(
                        "Failed to delete rule %s: %s",
                        rule,
                        e,
                    )

            # Delete archives for event bus
            event_source_arn = (
                f"arn:aws:events:{region_name}:{account_id}:event-bus/{event_bus_name}"
            )
            response = aws_client.events.list_archives(EventSourceArn=event_source_arn)
            archives = [archive["ArchiveName"] for archive in response["Archives"]]
            for archive in archives:
                try:
                    aws_client.events.delete_archive(ArchiveName=archive)
                except Exception as e:
                    LOG.warning(
                        "Failed to delete archive %s: %s",
                        archive,
                        e,
                    )

            aws_client.events.delete_event_bus(Name=event_bus_name)
        except Exception as e:
            LOG.warning(
                "Failed to delete event bus %s: %s",
                event_bus_name,
                e,
            )


@pytest.fixture
def events_create_default_or_custom_event_bus(events_create_event_bus, region_name, account_id):
    def _create_default_or_custom_event_bus(event_bus_type: str = "default"):
        if event_bus_type == "default":
            event_bus_name = "default"
            event_bus_arn = f"arn:{get_partition(region_name)}:events:{region_name}:{account_id}:event-bus/default"
        else:
            event_bus_name = f"test-bus-{short_uid()}"
            response = events_create_event_bus(Name=event_bus_name)
            event_bus_arn = response["EventBusArn"]
        return event_bus_name, event_bus_arn

    return _create_default_or_custom_event_bus


@pytest.fixture
def create_role_event_bus_source_to_bus_target(create_iam_role_with_policy):
    def _create_role_event_bus_to_bus():
        assume_role_policy_document_bus_source_to_bus_target = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }

        policy_document_bus_source_to_bus_target = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "",
                    "Effect": "Allow",
                    "Action": "events:PutEvents",
                    "Resource": "arn:aws:events:*:*:event-bus/*",
                }
            ],
        }

        role_arn_bus_source_to_bus_target = create_iam_role_with_policy(
            RoleDefinition=assume_role_policy_document_bus_source_to_bus_target,
            PolicyDefinition=policy_document_bus_source_to_bus_target,
        )

        return role_arn_bus_source_to_bus_target

    yield _create_role_event_bus_to_bus


@pytest.fixture
def events_put_rule(aws_client):
    rules = []

    def _put_rule(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"rule-{short_uid()}"

        response = aws_client.events.put_rule(**kwargs)
        rules.append((kwargs["Name"], kwargs.get("EventBusName", "default")))
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
            LOG.warning(
                "Failed to delete rule %s: %s",
                rule,
                e,
            )


@pytest.fixture
def events_create_archive(aws_client, region_name, account_id):
    archives = []

    def _create_archive(**kwargs):
        if "ArchiveName" not in kwargs:
            kwargs["ArchiveName"] = f"test-archive-{short_uid()}"

        if "EventSourceArn" not in kwargs:
            kwargs["EventSourceArn"] = (
                f"arn:aws:events:{region_name}:{account_id}:event-bus/default"
            )

        response = aws_client.events.create_archive(**kwargs)
        archives.append(kwargs["ArchiveName"])
        return response

    yield _create_archive

    for archive in archives:
        try:
            aws_client.events.delete_archive(ArchiveName=archive)
        except Exception as e:
            LOG.warning(
                "Failed to delete archive %s: %s",
                archive,
                e,
            )


@pytest.fixture
def put_event_to_archive(aws_client, events_create_event_bus, events_create_archive):
    def _put_event_to_archive(
        archive_name: str | None = None,
        event_pattern: dict | None = None,
        event_bus_name: str | None = None,
        event_source_arn: str | None = None,
        entries: list[dict] | None = None,
        num_events: int = 1,
    ):
        if not event_bus_name:
            event_bus_name = f"test-bus-{short_uid()}"
        if not event_source_arn:
            response = events_create_event_bus(Name=event_bus_name)
            event_source_arn = response["EventBusArn"]
        if not archive_name:
            archive_name = f"test-archive-{short_uid()}"

        response = events_create_archive(
            ArchiveName=archive_name,
            EventSourceArn=event_source_arn,
            EventPattern=json.dumps(event_pattern),
            RetentionDays=1,
        )
        archive_arn = response["ArchiveArn"]

        if entries:
            num_events = len(entries)
        else:
            entries = []
            for i in range(num_events):
                entries.append(
                    {
                        "Source": "testSource",
                        "DetailType": "testDetailType",
                        "Detail": f"event number {i}",
                        "EventBusName": event_bus_name,
                    }
                )

        aws_client.events.put_events(
            Entries=entries,
        )

        def wait_for_archive_event_count():
            response = aws_client.events.describe_archive(ArchiveName=archive_name)
            event_count = response["EventCount"]
            assert event_count == num_events

        retry(
            wait_for_archive_event_count, retries=35, sleep=10
        )  # events are batched and sent to the archive, this mostly takes at least 5 minutes on AWS

        return {
            "ArchiveName": archive_name,
            "ArchiveArn": archive_arn,
            "EventBusName": event_bus_name,
            "EventBusArn": event_source_arn,
        }

    yield _put_event_to_archive


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
def put_events_with_filter_to_sqs(
    aws_client, events_create_event_bus, events_put_rule, create_sqs_events_target
):
    def _put_events_with_filter_to_sqs(
        pattern: dict,
        entries_asserts: list[Tuple[list[dict], bool]],
        event_bus_name: str = None,
        input_path: str = None,
        input_transformer: dict[dict, str] = None,
    ):
        rule_name = f"test-rule-{short_uid()}"
        target_id = f"test-target-{short_uid()}"
        if not event_bus_name:
            event_bus_name = f"test-bus-{short_uid()}"
            events_create_event_bus(Name=event_bus_name)

        queue_url, queue_arn = create_sqs_events_target()

        events_put_rule(
            Name=rule_name,
            EventBusName=event_bus_name,
            EventPattern=json.dumps(pattern),
        )

        kwargs = {"InputPath": input_path} if input_path else {}
        if input_transformer:
            kwargs["InputTransformer"] = input_transformer

        response = aws_client.events.put_targets(
            Rule=rule_name,
            EventBusName=event_bus_name,
            Targets=[{"Id": target_id, "Arn": queue_arn, **kwargs}],
        )

        assert response["FailedEntryCount"] == 0
        assert response["FailedEntries"] == []

        messages = []
        for entry_asserts in entries_asserts:
            entries = entry_asserts[0]
            for entry in entries:
                entry["EventBusName"] = event_bus_name
            message = put_entries_assert_results_sqs(
                aws_client.events,
                aws_client.sqs,
                queue_url,
                entries=entries,
                should_match=entry_asserts[1],
            )
            if message is not None:
                messages.extend(message)

        return messages

    yield _put_events_with_filter_to_sqs


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
def get_primary_secondary_client(
    aws_client_factory,
    secondary_aws_client_factory,
    region_name,
    secondary_region_name,
    account_id,
    secondary_account_id,
):
    def _get_primary_secondary_clients(cross_scenario: str):
        secondary_region = secondary_region_name
        secondary_account = secondary_account_id
        if cross_scenario not in ["region", "account", "region_account"]:
            raise ValueError(f"cross_scenario {cross_scenario} not supported")

        primary_client = aws_client_factory(region_name=region_name)

        if cross_scenario == "region":
            secondary_account = account_id
            secondary_client = aws_client_factory(region_name=secondary_region_name)

        elif cross_scenario == "account":
            secondary_region = region_name
            secondary_client = secondary_aws_client_factory(region_name=region_name)

        elif cross_scenario == "region_account":
            secondary_client = secondary_aws_client_factory(region_name=secondary_region)

        else:
            raise ValueError(f"cross_scenario {cross_scenario} not supported")

        return {
            "primary_aws_client": primary_client,
            "secondary_aws_client": secondary_client,
            "secondary_region_name": secondary_region,
            "secondary_account_id": secondary_account,
        }

    return _get_primary_secondary_clients
