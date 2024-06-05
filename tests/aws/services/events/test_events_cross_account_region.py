import json
import time

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.helper_functions import sqs_collect_messages
from tests.aws.services.events.test_events import EVENT_DETAIL, TEST_EVENT_PATTERN_NO_SOURCE

SOURCE_PRIMARY = "source-primary"
SOURCE_SECONDARY = "source-secondary"


class TestEventCrossRegion:
    @markers.aws.validated
    def test_event_bus_to_event_bus_cross_region(
        self, aws_client_factory, cleanups, sqs_get_queue_arn, snapshot
    ):
        primary_region = "us-east-1"
        secondary_region = "eu-central-1"

        # overwriting randomized region https://docs.localstack.cloud/contributing/multi-account-region-testing/
        # requires manually adding region replacement for snapshot
        snapshot.add_transformer(snapshot.transform.regex(primary_region, "<region>"))
        snapshot.add_transformer(snapshot.transform.regex(secondary_region, "<region>"))

        aws_client_primary = aws_client_factory(region_name=primary_region)
        aws_client_secondary = aws_client_factory(region_name=secondary_region)

        # Create event buses
        event_bus_name_primary = f"test-event-bus-primary-{short_uid()}"
        aws_client_primary.events.create_event_bus(Name=event_bus_name_primary)["EventBusArn"]
        cleanups.append(
            lambda: aws_client_primary.events.delete_event_bus(Name=event_bus_name_primary)
        )

        event_bus_name_secondary = f"test-event-bus-secondary-{short_uid()}"
        event_bus_arn_secondary = aws_client_secondary.events.create_event_bus(
            Name=event_bus_name_secondary
        )["EventBusArn"]
        cleanups.append(
            lambda: aws_client_secondary.events.delete_event_bus(Name=event_bus_name_secondary)
        )

        # Create SQS queues
        queue_name_primary = f"test-queue-primary-{short_uid()}"
        queue_url_primary = aws_client_primary.sqs.create_queue(QueueName=queue_name_primary)[
            "QueueUrl"
        ]
        cleanups.append(lambda: aws_client_primary.sqs.delete_queue(QueueUrl=queue_url_primary))
        queue_arn_primary = aws_client_primary.sqs.get_queue_attributes(
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
        aws_client_primary.sqs.set_queue_attributes(
            QueueUrl=queue_url_primary, Attributes={"Policy": json.dumps(policy_events_sqs_primary)}
        )

        queue_name_secondary = f"test-queue-secondary-{short_uid()}"
        queue_url_secondary = aws_client_secondary.sqs.create_queue(QueueName=queue_name_secondary)[
            "QueueUrl"
        ]
        cleanups.append(lambda: aws_client_secondary.sqs.delete_queue(QueueUrl=queue_url_secondary))
        queue_arn_secondary = aws_client_secondary.sqs.get_queue_attributes(
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
        aws_client_secondary.sqs.set_queue_attributes(
            QueueUrl=queue_url_secondary,
            Attributes={"Policy": json.dumps(policy_events_sqs_secondary)},
        )

        # Create rule in primary region
        rule_name = f"test-rule-primary-sqs-{short_uid()}"
        aws_client_primary.events.put_rule(
            Name=rule_name,
            EventPattern=json.dumps({"source": [SOURCE_PRIMARY]}),
            # EventPattern=json.dumps({"source": [SOURCE_PRIMARY], **TEST_EVENT_PATTERN_NO_SOURCE}),
            EventBusName=event_bus_name_primary,
        )
        cleanups.append(lambda: aws_client_primary.events.delete_rule(Name=rule_name))

        # Create target in primary region sqs
        target_id_sqs_primary = f"test-target-primary-sqs-{short_uid()}"
        aws_client_primary.events.put_targets(
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
        role_name_bus_primary_to_bus_secondary = (
            f"event-bus-primary-to-secondary-role-{short_uid()}"
        )
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

        role_arn_bus_primary_to_bus_secondary = aws_client_primary.iam.create_role(
            RoleName=role_name_bus_primary_to_bus_secondary,
            AssumeRolePolicyDocument=json.dumps(
                assume_role_policy_document_bus_primary_to_bus_secondary
            ),
        )["Role"]["Arn"]
        cleanups.append(
            lambda: aws_client_primary.iam.delete_role(
                RoleName=role_name_bus_primary_to_bus_secondary
            )
        )

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

        aws_client_primary.iam.put_role_policy(
            RoleName=role_name_bus_primary_to_bus_secondary,
            PolicyName=policy_name_bus_primary_to_bus_secondary,
            PolicyDocument=json.dumps(policy_document_bus_primary_to_bus_secondary),
        )
        cleanups.append(
            lambda: aws_client_primary.iam.delete_role_policy(
                RoleName=role_name_bus_primary_to_bus_secondary,
                PolicyName=policy_name_bus_primary_to_bus_secondary,
            )
        )

        if is_aws_cloud():
            time.sleep(10)

        # Create target in primary region event bus secondary region
        target_id_event_bus_secondary = f"test-target-primary-events-{short_uid()}"
        aws_client_primary.events.put_targets(
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

        cleanups.append(
            lambda: aws_client_primary.events.remove_targets(
                Rule=rule_name,
                EventBusName=event_bus_name_primary,
                Ids=[target_id_sqs_primary, target_id_event_bus_secondary],
            )
        )

        # Create rule in secondary region
        rule_name_secondary = f"test-rule-secondary-sqs-{short_uid()}"
        aws_client_secondary.events.put_rule(
            Name=rule_name_secondary,
            EventPattern=json.dumps({"source": [SOURCE_PRIMARY, SOURCE_SECONDARY]}),
            EventBusName=event_bus_name_secondary,
        )
        cleanups.append(lambda: aws_client_secondary.events.delete_rule(Name=rule_name_secondary))

        # Create target in secondary region sqs
        target_id_sqs_secondary = f"test-target-secondary-{short_uid()}"
        aws_client_secondary.events.put_targets(
            Rule=rule_name_secondary,
            EventBusName=event_bus_name_secondary,
            Targets=[
                {
                    "Id": target_id_sqs_secondary,
                    "Arn": queue_arn_secondary,
                }
            ],
        )

        # Put events into primary event bus
        aws_client_primary.events.put_events(
            Entries=[
                {
                    "Source": SOURCE_PRIMARY,
                    "DetailType": TEST_EVENT_PATTERN_NO_SOURCE["detail-type"][0],
                    "Detail": json.dumps(EVENT_DETAIL),
                    "EventBusName": event_bus_name_primary,
                }
            ],
        )
        # aws_client_primary.events.put_events(
        #     Entries=[
        #         {
        #             "Source": "source-secondary",
        #             "DetailType": "test-event",
        #             "Detail": json.dumps(EVENT_DETAIL),
        #             "EventBusName": event_bus_name_primary,
        #         }
        #     ],
        # )

        # Collect messages from primary queue
        messages_primary = sqs_collect_messages(
            aws_client_primary, queue_url_primary, min_events=1, wait_time=1, retries=5
        )
        snapshot.match("messages_primary_queue_from_primary_event_bus", messages_primary)

        # # Collect messages from secondary queue
        messages_secondary = sqs_collect_messages(
            aws_client_secondary, queue_url_secondary, min_events=1, wait_time=1, retries=5
        )
        snapshot.match("messages_secondary_queue_from_primary_event_bus", messages_secondary)

        # Put events into secondary event bus
        aws_client_secondary.events.put_events(
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
            aws_client_secondary, queue_url_secondary, min_events=2, wait_time=1, retries=5
        )
        snapshot.match("messages_secondary_queue_from_secondary_event_bus", messages_secondary)
