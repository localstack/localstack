import json
import time

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.helper_functions import is_old_provider, sqs_collect_messages
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN_NO_SOURCE

SOURCE_PRIMARY = "source-primary"
SOURCE_SECONDARY = "source-secondary"


@markers.aws.validated
@pytest.mark.skipif(is_old_provider(), reason="Not supported in v1 provider")
@pytest.mark.parametrize("cross_scenario", ["region", "account", "region_account"])
@pytest.mark.parametrize("event_bus_name", ["default", "custom"])
def test_event_bus_to_event_bus_cross_account_region(
    cross_scenario,
    event_bus_name,
    region_name,
    secondary_region_name,
    account_id,
    secondary_account_id,
    aws_client_factory,
    secondary_aws_client_factory,
    cleanups,
    snapshot,
):
    # overwriting randomized region https://docs.localstack.cloud/contributing/multi-account-region-testing/
    # requires manually adding region replacement for snapshot
    snapshot.add_transformer(snapshot.transform.regex(region_name, "<region>"))
    snapshot.add_transformer(snapshot.transform.regex(secondary_region_name, "<region-secondary>"))
    snapshot.add_transformer(snapshot.transform.regex(account_id, "<account>"))
    snapshot.add_transformer(snapshot.transform.regex(secondary_account_id, "<account-secondary>"))

    # Create aws clients
    if cross_scenario == "region":
        secondary_account_id = account_id
        aws_client = aws_client_factory(region_name=region_name)
        secondary_aws_client = aws_client_factory(region_name=secondary_region_name)
    if cross_scenario == "account":
        secondary_region_name = region_name
        aws_client = aws_client_factory(region_name=region_name)
        secondary_aws_client = secondary_aws_client_factory(region_name=region_name)
    if cross_scenario == "region_account":
        aws_client = aws_client_factory(region_name=region_name)
        secondary_aws_client = secondary_aws_client_factory(region_name=secondary_region_name)

    # Create event buses
    if event_bus_name == "default":
        event_bus_name_primary = "default"
        event_bus_name_secondary = "default"
        event_bus_arn_secondary = (
            f"arn:aws:events:{secondary_region_name}:{secondary_account_id}:event-bus/default"
        )
    if event_bus_name == "custom":
        event_bus_name_primary = f"test-event-bus-primary-{short_uid()}"
        aws_client.events.create_event_bus(Name=event_bus_name_primary)["EventBusArn"]

        event_bus_name_secondary = f"test-event-bus-secondary-{short_uid()}"
        event_bus_arn_secondary = secondary_aws_client.events.create_event_bus(
            Name=event_bus_name_secondary
        )["EventBusArn"]

    # Permission for event bus in secondary region to receive events to event bus in primary region
    secondary_aws_client.events.put_permission(
        StatementId=f"SecondaryEventBusAccessPermission{short_uid()}",
        EventBusName=event_bus_name_secondary,
        Action="events:PutEvents",
        Principal="*",
    )

    # Create SQS queues
    queue_name_primary = f"test-queue-primary-{short_uid()}"
    queue_url_primary = aws_client.sqs.create_queue(QueueName=queue_name_primary)["QueueUrl"]
    queue_arn_primary = aws_client.sqs.get_queue_attributes(
        QueueUrl=queue_url_primary, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy_events_sqs_primary = {
        "Version": "2012-10-17",
        "Id": f"sqs-eventbridge-{short_uid()}",
        "Statement": [
            {
                "Sid": f"SendMessage-{short_uid()}",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn_primary,
            }
        ],
    }
    aws_client.sqs.set_queue_attributes(
        QueueUrl=queue_url_primary, Attributes={"Policy": json.dumps(policy_events_sqs_primary)}
    )

    queue_name_secondary = f"test-queue-secondary-{short_uid()}"
    queue_url_secondary = secondary_aws_client.sqs.create_queue(QueueName=queue_name_secondary)[
        "QueueUrl"
    ]
    queue_arn_secondary = secondary_aws_client.sqs.get_queue_attributes(
        QueueUrl=queue_url_secondary, AttributeNames=["QueueArn"]
    )["Attributes"]["QueueArn"]
    policy_events_sqs_secondary = {
        "Version": "2012-10-17",
        "Id": f"sqs-eventbridge-{short_uid()}",
        "Statement": [
            {
                "Sid": f"SendMessage-{short_uid()}",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn_secondary,
            }
        ],
    }
    secondary_aws_client.sqs.set_queue_attributes(
        QueueUrl=queue_url_secondary,
        Attributes={"Policy": json.dumps(policy_events_sqs_secondary)},
    )

    # Create rule in primary region
    rule_name = f"test-rule-primary-sqs-{short_uid()}"
    aws_client.events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": [SOURCE_PRIMARY]}),
        # EventPattern=json.dumps({"source": [SOURCE_PRIMARY], **TEST_EVENT_PATTERN_NO_SOURCE}),
        EventBusName=event_bus_name_primary,
    )

    # Create target in primary region sqs
    target_id_sqs_primary = f"test-target-primary-sqs-{short_uid()}"
    aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=event_bus_name_primary,
        Targets=[
            {
                "Id": target_id_sqs_primary,
                "Arn": queue_arn_primary,
            }
        ],
    )

    # Create permission for event bus in primary region to send events to event bus in secondary region
    role_name_bus_primary_to_bus_secondary = f"event-bus-primary-to-secondary-role-{short_uid()}"
    assume_role_policy_document_bus_primary_to_bus_secondary = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    role_arn_bus_primary_to_bus_secondary = aws_client.iam.create_role(
        RoleName=role_name_bus_primary_to_bus_secondary,
        AssumeRolePolicyDocument=json.dumps(
            assume_role_policy_document_bus_primary_to_bus_secondary
        ),
    )["Role"]["Arn"]

    policy_name_bus_primary_to_bus_secondary = (
        f"event-bus-primary-to-secondary-policy-{short_uid()}"
    )
    policy_document_bus_primary_to_bus_secondary = {
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

    aws_client.iam.put_role_policy(
        RoleName=role_name_bus_primary_to_bus_secondary,
        PolicyName=policy_name_bus_primary_to_bus_secondary,
        PolicyDocument=json.dumps(policy_document_bus_primary_to_bus_secondary),
    )

    if is_aws_cloud():
        time.sleep(10)

    # Create target in primary region event bus secondary region
    target_id_event_bus_secondary = f"test-target-primary-events-{short_uid()}"
    aws_client.events.put_targets(
        Rule=rule_name,
        EventBusName=event_bus_name_primary,
        Targets=[
            {
                "Id": target_id_event_bus_secondary,
                "Arn": event_bus_arn_secondary,
                "RoleArn": role_arn_bus_primary_to_bus_secondary,
            }
        ],
    )

    # Create rule in secondary region
    rule_name_secondary = f"test-rule-secondary-sqs-{short_uid()}"
    secondary_aws_client.events.put_rule(
        Name=rule_name_secondary,
        EventPattern=json.dumps({"source": [SOURCE_PRIMARY, SOURCE_SECONDARY]}),
        EventBusName=event_bus_name_secondary,
    )
    cleanups.append(lambda: secondary_aws_client.events.delete_rule(Name=rule_name_secondary))

    # Create target in secondary region sqs
    target_id_sqs_secondary = f"test-target-secondary-{short_uid()}"
    secondary_aws_client.events.put_targets(
        Rule=rule_name_secondary,
        EventBusName=event_bus_name_secondary,
        Targets=[
            {
                "Id": target_id_sqs_secondary,
                "Arn": queue_arn_secondary,
            }
        ],
    )

    ######
    # Test
    ######

    # Put events into primary event bus
    aws_client.events.put_events(
        Entries=[
            {
                "Source": SOURCE_PRIMARY,
                "DetailType": TEST_EVENT_PATTERN_NO_SOURCE["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
                "EventBusName": event_bus_name_primary,
            }
        ],
    )

    # Collect messages from primary queue
    messages_primary = sqs_collect_messages(
        aws_client, queue_url_primary, expected_events_count=1, wait_time=1, retries=5
    )
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("ReceiptHandle", reference_replacement=False),
            snapshot.transform.key_value("MD5OfBody", reference_replacement=False),
        ],
    )
    snapshot.match("messages_primary_queue_from_primary_event_bus", messages_primary)

    # # Collect messages from secondary queue
    messages_secondary = sqs_collect_messages(
        secondary_aws_client,
        queue_url_secondary,
        expected_events_count=1,
        wait_time=1,
        retries=5,
    )
    snapshot.match("messages_secondary_queue_from_primary_event_bus", messages_secondary)

    # Put events into secondary event bus
    secondary_aws_client.events.put_events(
        Entries=[
            {
                "Source": SOURCE_SECONDARY,
                "DetailType": TEST_EVENT_PATTERN_NO_SOURCE["detail-type"][0],
                "Detail": json.dumps(EVENT_DETAIL),
                "EventBusName": event_bus_name_secondary,
            }
        ],
    )

    # Collect messages from secondary queue
    messages_secondary = sqs_collect_messages(
        secondary_aws_client,
        queue_url_secondary,
        expected_events_count=1,
        wait_time=1,
        retries=5,
    )
    snapshot.match("messages_secondary_queue_from_secondary_event_bus", messages_secondary)

    # Custom cleanup
    aws_client.events.remove_targets(
        Rule=rule_name,
        EventBusName=event_bus_name_primary,
        Ids=[target_id_sqs_primary, target_id_event_bus_secondary],
    )
    aws_client.events.delete_rule(EventBusName=event_bus_name_primary, Name=rule_name)
    try:
        aws_client.events.delete_event_bus(
            Name=event_bus_name_primary
        )  # default bus cannot be deleted
    except Exception:
        pass

    secondary_aws_client.events.remove_targets(
        Rule=rule_name_secondary,
        EventBusName=event_bus_name_secondary,
        Ids=[target_id_sqs_secondary],
    )
    secondary_aws_client.events.delete_rule(
        EventBusName=event_bus_name_secondary, Name=rule_name_secondary
    )
    try:
        secondary_aws_client.events.delete_event_bus(
            Name=event_bus_name_secondary
        )  # default bus cannot be deleted
    except Exception:
        pass

    aws_client.sqs.delete_queue(QueueUrl=queue_url_primary)
    secondary_aws_client.sqs.delete_queue(QueueUrl=queue_url_secondary)

    aws_client.iam.delete_role_policy(
        RoleName=role_name_bus_primary_to_bus_secondary,
        PolicyName=policy_name_bus_primary_to_bus_secondary,
    )
    aws_client.iam.delete_role(RoleName=role_name_bus_primary_to_bus_secondary)
