import json

import pytest

from localstack.config import LEGACY_S3_PROVIDER
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@pytest.fixture
def basic_event_bridge_rule_to_sqs_queue(
    s3_client,
    s3_create_bucket,
    events_create_rule,
    sqs_create_queue,
    sqs_queue_arn,
    sqs_client,
    events_client,
):
    bus_name = "default"
    queue_name = f"test-queue-{short_uid()}"
    bucket_name = f"test-bucket-{short_uid()}"
    rule_name = f"test-rule-{short_uid()}"
    target_id = f"test-target-{short_uid()}"

    s3_create_bucket(Bucket=bucket_name)
    s3_client.put_bucket_notification_configuration(
        Bucket=bucket_name, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )

    pattern = {
        "source": ["aws.s3"],
        "detail-type": [
            "Object Created",
            "Object Deleted",
            "Object Restore Initiated",
            "Object Restore Completed",
            "Object Restore Expired",
            "Object Tags Added",
            "Object Tags Deleted",
            "Object ACL Updated",
            "Object Storage Class Changed",
            "Object Access Tier Changed",
        ],
        "detail": {"bucket": {"name": [bucket_name]}},
    }
    rule_arn = events_create_rule(Name=rule_name, EventBusName=bus_name, EventPattern=pattern)

    queue_url = sqs_create_queue(QueueName=queue_name)
    queue_arn = sqs_queue_arn(queue_url)
    queue_policy = {
        "Statement": [
            {
                "Sid": "EventsToMyQueue",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
            }
        ]
    }
    sqs_client.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(queue_policy), "ReceiveMessageWaitTimeSeconds": "5"},
    )
    events_client.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

    return bucket_name, queue_url


@pytest.fixture(autouse=True)
def s3_event_bridge_notification(snapshot):
    snapshot.add_transformer(snapshot.transform.s3_api())
    snapshot.add_transformers_list(
        [
            snapshot.transform.jsonpath("$..detail.bucket.name", "bucket-name"),
            snapshot.transform.jsonpath("$..detail.object.key", "key-name"),
            snapshot.transform.jsonpath(
                "$..detail.object.sequencer", "object-sequencer", reference_replacement=False
            ),
            snapshot.transform.jsonpath(
                "$..detail.request-id", "request-id", reference_replacement=False
            ),
            snapshot.transform.jsonpath(
                "$..detail.requester", "<requester>", reference_replacement=False
            ),
            snapshot.transform.jsonpath("$..detail.source-ip-address", "ip-address"),
        ]
    )


class TestS3NotificationsToEventBridge:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..detail.object.etag"]
    )
    def test_object_created_put(
        self,
        s3_client,
        sqs_client,
        basic_event_bridge_rule_to_sqs_queue,
        snapshot,
    ):
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue

        test_key = "test-key"
        s3_client.put_object(Bucket=bucket_name, Key=test_key, Body=b"data")
        s3_client.delete_object(Bucket=bucket_name, Key=test_key)

        messages = {}

        def _receive_messages():
            received = sqs_client.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                event_message = json.loads(msg["Body"])
                messages.update({event_message["detail-type"]: event_message})

            assert len(messages) == 2

        retries = 10 if is_aws_cloud() else 5
        retry(_receive_messages, retries=retries)
        object_deleted_event = messages["Object Deleted"]
        object_created_event = messages["Object Created"]
        snapshot.match("object_deleted", object_deleted_event)
        snapshot.match("object_created", object_created_event)
        # assert that the request-id is randomly generated
        # ideally, it should use the true request-id. However, the request-id is set in the serializer for now,
        # and would need to be set before going through the skeleton
        assert (
            object_deleted_event["detail"]["request-id"]
            != object_created_event["detail"]["request-id"]
        )

    @pytest.mark.aws_validated
    @pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="not implemented")
    def test_object_put_acl(
        self,
        s3_client,
        sqs_client,
        basic_event_bridge_rule_to_sqs_queue,
        snapshot,
    ):

        # setup fixture
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue
        key_name = "my_key_acl"

        s3_client.put_object(Bucket=bucket_name, Key=key_name, Body="something")
        list_bucket_output = s3_client.list_buckets()
        owner = list_bucket_output["Owner"]

        # change the ACL to the default one, it should not send an Event. Use canned ACL first
        s3_client.put_object_acl(Bucket=bucket_name, Key=key_name, ACL="private")
        # change the ACL, it should not send an Event. Use canned ACL first
        s3_client.put_object_acl(Bucket=bucket_name, Key=key_name, ACL="public-read")
        # try changing ACL with Grant
        s3_client.put_object_acl(
            Bucket=bucket_name,
            Key=key_name,
            GrantRead='uri="http://acs.amazonaws.com/groups/s3/LogDelivery"',
        )
        # try changing ACL with ACP
        acp = {
            "Owner": owner,
            "Grants": [
                {
                    "Grantee": {"ID": owner["ID"], "Type": "CanonicalUser"},
                    "Permission": "FULL_CONTROL",
                },
                {
                    "Grantee": {
                        "URI": "http://acs.amazonaws.com/groups/s3/LogDelivery",
                        "Type": "Group",
                    },
                    "Permission": "WRITE",
                },
            ],
        }
        s3_client.put_object_acl(Bucket=bucket_name, Key=key_name, AccessControlPolicy=acp)

        messages = []

        def _receive_messages():
            received = sqs_client.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                event_message = json.loads(msg["Body"])
                messages.append(event_message)

            assert len(messages) == 4

        retries = 10 if is_aws_cloud() else 5
        retry(_receive_messages, retries=retries, sleep=0.1)
        messages.sort(key=lambda x: x["time"])
        snapshot.match("messages", {"messages": messages})
