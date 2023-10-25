import json

import pytest

from localstack.constants import SECONDARY_TEST_AWS_REGION_NAME
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@pytest.fixture
def basic_event_bridge_rule_to_sqs_queue(
    s3_create_bucket, events_create_rule, sqs_create_queue, sqs_get_queue_arn, aws_client
):
    bus_name = "default"
    queue_name = f"test-queue-{short_uid()}"
    bucket_name = f"test-bucket-{short_uid()}"
    rule_name = f"test-rule-{short_uid()}"
    target_id = f"test-target-{short_uid()}"

    s3_create_bucket(Bucket=bucket_name)
    aws_client.s3.put_bucket_notification_configuration(
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
    queue_arn = sqs_get_queue_arn(queue_url)
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
    aws_client.sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(queue_policy), "ReceiveMessageWaitTimeSeconds": "5"},
    )
    aws_client.events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

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
    @markers.aws.validated
    def test_object_created_put(self, basic_event_bridge_rule_to_sqs_queue, snapshot, aws_client):
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue

        test_key = "test-key"
        aws_client.s3.put_object(Bucket=bucket_name, Key=test_key, Body=b"data")
        aws_client.s3.delete_object(Bucket=bucket_name, Key=test_key)

        messages = {}

        def _receive_messages():
            received = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
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

    @markers.aws.validated
    def test_object_put_acl(self, basic_event_bridge_rule_to_sqs_queue, snapshot, aws_client):
        # setup fixture
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue
        aws_client.s3.delete_bucket_ownership_controls(Bucket=bucket_name)
        aws_client.s3.delete_public_access_block(Bucket=bucket_name)
        key_name = "my_key_acl"

        aws_client.s3.put_object(Bucket=bucket_name, Key=key_name, Body="something")
        list_bucket_output = aws_client.s3.list_buckets()
        owner = list_bucket_output["Owner"]

        # change the ACL to the default one, it should not send an Event. Use canned ACL first
        aws_client.s3.put_object_acl(Bucket=bucket_name, Key=key_name, ACL="private")
        # change the ACL, it should not send an Event. Use canned ACL first
        aws_client.s3.put_object_acl(Bucket=bucket_name, Key=key_name, ACL="public-read")
        # try changing ACL with Grant
        aws_client.s3.put_object_acl(
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
        aws_client.s3.put_object_acl(Bucket=bucket_name, Key=key_name, AccessControlPolicy=acp)

        messages = []

        def _receive_messages():
            received = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                event_message = json.loads(msg["Body"])
                messages.append(event_message)

            assert len(messages) == 4

        retries = 10 if is_aws_cloud() else 5
        retry(_receive_messages, retries=retries, sleep=0.1)
        messages.sort(key=lambda x: (x["detail-type"], x["time"]))
        snapshot.match("messages", {"messages": messages})

    @markers.aws.validated
    def test_restore_object(self, basic_event_bridge_rule_to_sqs_queue, snapshot, aws_client):
        # setup fixture
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue
        key_name = "my_key_restore"

        # We set the StorageClass to Glacier Flexible Retrieval (formerly Glacier) as it's the only one allowing
        # Expedited retrieval Tier (with the Intelligent Access Archive tier)
        aws_client.s3.put_object(
            Bucket=bucket_name, Key=key_name, Body="something", StorageClass="GLACIER"
        )

        aws_client.s3.restore_object(
            Bucket=bucket_name,
            Key=key_name,
            RestoreRequest={
                "Days": 1,
                "GlacierJobParameters": {
                    "Tier": "Expedited",  # Set it as Expedited, it should be done within 1-5min
                },
            },
        )

        def _is_object_restored():
            resp = aws_client.s3.head_object(Bucket=bucket_name, Key=key_name)
            assert 'ongoing-request="false"' in resp["Restore"]

        if is_aws_cloud():
            retries = 12
            sleep = 30
        else:
            retries = 3
            sleep = 1

        retry(_is_object_restored, retries=retries, sleep=sleep)

        messages = []

        def _receive_messages():
            received = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                event_message = json.loads(msg["Body"])
                # skip PutObject
                if event_message["detail-type"] != "Object Created":
                    messages.append(event_message)
                aws_client.sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )

            assert len(messages) == 2

        retries = 20 if is_aws_cloud() else 5
        retry(_receive_messages, retries=retries, sleep=0.1)
        messages.sort(key=lambda x: x["time"])
        snapshot.match("messages", {"messages": messages})

    @markers.aws.validated
    def test_object_created_put_in_different_region(
        self, basic_event_bridge_rule_to_sqs_queue, snapshot, aws_client_factory, aws_client
    ):
        snapshot.add_transformer(snapshot.transform.key_value("region"), priority=-1)
        # create the bucket and the queue URL in the default region
        bucket_name, queue_url = basic_event_bridge_rule_to_sqs_queue

        # create an S3 client in another region, to verify the region in the event
        s3_client = aws_client_factory(region_name=SECONDARY_TEST_AWS_REGION_NAME).s3
        test_key = "test-key"
        s3_client.put_object(Bucket=bucket_name, Key=test_key, Body=b"data")
        aws_client.s3.put_object(Bucket=bucket_name, Key=test_key, Body=b"data")

        messages = []

        def _receive_messages():
            received = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                event_message = json.loads(msg["Body"])
                messages.append(event_message)

            assert len(messages) == 2

        retries = 10 if is_aws_cloud() else 5
        retry(_receive_messages, retries=retries)
        snapshot.match("object-created-different-regions", {"messages": messages})
        assert messages[0]["region"] == messages[1]["region"] == aws_client.s3.meta.region_name
