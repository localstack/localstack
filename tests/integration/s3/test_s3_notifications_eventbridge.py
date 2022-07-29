import json

import pytest

from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


class TestS3NotificationsToEventBridge:
    @pytest.mark.aws_validated
    def test_object_created_put(
        self,
        s3_client,
        s3_create_bucket,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        events_client,
        events_create_rule,
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

        test_key = "test-key"
        s3_client.put_object(Bucket=bucket_name, Key=test_key, Body=b"data")
        s3_client.delete_object(Bucket=bucket_name, Key=test_key)

        messages = {}

        def _validate_messages():
            received = sqs_client.receive_message(QueueUrl=queue_url).get("Messages", [])
            for msg in received:
                messages.update({msg["MessageId"]: msg})
            assert len(messages) == 2
            messages_array = list(messages.values())

            delete_event_message = json.loads(messages_array[0]["Body"])
            create_event_message = json.loads(messages_array[1]["Body"])

            assert delete_event_message["detail-type"] == "Object Deleted"
            assert create_event_message["detail-type"] == "Object Created"

            assert delete_event_message["source"] == "aws.s3"
            assert create_event_message["source"] == "aws.s3"

            assert delete_event_message["detail"]["bucket"]["name"] == bucket_name
            assert create_event_message["detail"]["bucket"]["name"] == bucket_name

            assert delete_event_message["detail"]["object"]["key"] == test_key
            assert create_event_message["detail"]["object"]["key"] == test_key

        retry(_validate_messages)
