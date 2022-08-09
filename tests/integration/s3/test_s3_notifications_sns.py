import json
import logging
from typing import TYPE_CHECKING, Dict, List

import pytest

from localstack.utils.aws import aws_stack
from localstack.utils.sync import poll_condition

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_s3.literals import EventType
    from mypy_boto3_sns import SNSClient
    from mypy_boto3_sqs import SQSClient

LOG = logging.getLogger(__name__)


def create_sns_bucket_notification(
    s3_client: "S3Client",
    sns_client: "SNSClient",
    bucket_name: str,
    topic_arn: str,
    events: List["EventType"],
):
    """A NotificationFactory."""
    bucket_arn = aws_stack.s3_bucket_arn(bucket_name)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sns:Publish",
                "Resource": topic_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
            }
        ],
    }
    sns_client.set_topic_attributes(
        TopicArn=topic_arn, AttributeName="Policy", AttributeValue=json.dumps(policy)
    )

    s3_client.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration=dict(
            TopicConfigurations=[
                dict(
                    TopicArn=topic_arn,
                    Events=events,
                )
            ]
        ),
    )


def sqs_collect_sns_messages(
    sqs_client: "SQSClient", queue_url: str, min_messages: int, timeout: int = 10
) -> List[Dict]:
    """
    Polls the given queue for the given amount of time and extracts the received SQS messages all SNS messages (messages that have a "TopicArn" field).

    :param sqs_client: the boto3 client to use
    :param queue_url: the queue URL connected to the topic
    :param min_messages: the minimum number of messages to wait for
    :param timeout: the number of seconds to wait before raising an assert error
    :return: a list with the deserialized SNS messages
    """

    collected_messages = []

    def collect_events() -> int:
        _response = sqs_client.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=timeout, MaxNumberOfMessages=1
        )
        messages = _response.get("Messages", [])
        if not messages:
            LOG.info("no messages received from %s after %d seconds", queue_url, timeout)

        for m in messages:
            body = m["Body"]
            # see https://www.mikulskibartosz.name/what-is-s3-test-event/
            if "s3:TestEvent" in body:
                continue

            doc = json.loads(body)
            assert "TopicArn" in doc, f"unexpected event in message {m}"
            collected_messages.append(doc)

        return len(collected_messages)

    assert poll_condition(lambda: collect_events() >= min_messages, timeout=timeout)

    return collected_messages


class TestS3NotificationsToSns:
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(paths=["$..s3.object.eTag", "$..s3.object.versionId"])
    def test_object_created_put(
        self,
        s3_client,
        sqs_client,
        sns_client,
        s3_create_bucket,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = s3_create_bucket()
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        key_name = "bucket-key"

        # connect topic to queue
        sns_create_sqs_subscription(topic_arn, queue_url)
        create_sns_bucket_notification(
            s3_client, sns_client, bucket_name, topic_arn, ["s3:ObjectCreated:*"]
        )

        # trigger the events
        s3_client.put_object(Bucket=bucket_name, Key=key_name, Body="first event")
        s3_client.put_object(Bucket=bucket_name, Key=key_name, Body="second event")

        # collect messages
        messages = sqs_collect_sns_messages(sqs_client, queue_url, 2)
        # order seems not be guaranteed - sort so we can rely on the order
        messages.sort(key=lambda x: json.loads(x["Message"])["Records"][0]["s3"]["object"]["size"])
        snapshot.match("receive_messages", {"messages": messages})
        # asserts
        # first event
        message = messages[0]
        assert message["Type"] == "Notification"
        assert message["TopicArn"] == topic_arn
        assert message["Subject"] == "Amazon S3 Notification"

        event = json.loads(message["Message"])["Records"][0]
        assert event["eventSource"] == "aws:s3"
        assert event["eventName"] == "ObjectCreated:Put"
        assert event["s3"]["bucket"]["name"] == bucket_name
        assert event["s3"]["object"]["key"] == key_name
        assert event["s3"]["object"]["size"] == len("first event")

        # second event
        message = messages[1]
        assert message["Type"] == "Notification"
        assert message["TopicArn"] == topic_arn
        assert message["Subject"] == "Amazon S3 Notification"

        event = json.loads(message["Message"])["Records"][0]
        assert event["eventSource"] == "aws:s3"
        assert event["eventName"] == "ObjectCreated:Put"
        assert event["s3"]["bucket"]["name"] == bucket_name
        assert event["s3"]["object"]["key"] == key_name
        assert event["s3"]["object"]["size"] == len("second event")
