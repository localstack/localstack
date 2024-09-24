import json
import logging
from io import BytesIO
from typing import TYPE_CHECKING, Dict, List

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition
from tests.aws.services.s3.conftest import TEST_S3_IMAGE

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
    bucket_arn = arns.s3_bucket_arn(bucket_name)

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


@pytest.mark.skipif(condition=TEST_S3_IMAGE, reason="SNS not enabled in S3 image")
class TestS3NotificationsToSns:
    @markers.aws.validated
    def test_object_created_put(
        self,
        s3_bucket,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.sns_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        key_name = "bucket-key"

        # connect topic to queue
        sns_create_sqs_subscription(topic_arn, queue_url)
        create_sns_bucket_notification(
            aws_client.s3, aws_client.sns, s3_bucket, topic_arn, ["s3:ObjectCreated:*"]
        )

        # trigger the events
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="first event")
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="second event")

        # collect messages
        messages = sqs_collect_sns_messages(aws_client.sqs, queue_url, 2)
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
        assert event["s3"]["bucket"]["name"] == s3_bucket
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
        assert event["s3"]["bucket"]["name"] == s3_bucket
        assert event["s3"]["object"]["key"] == key_name
        assert event["s3"]["object"]["size"] == len("second event")

    @markers.aws.validated
    def test_bucket_notifications_with_filter(
        self,
        sqs_create_queue,
        sns_create_topic,
        s3_bucket,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        # Tests s3->sns->sqs notifications
        #
        queue_name = f"queue-{short_uid()}"
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)

        snapshot.add_transformer(snapshot.transform.regex(queue_name, "<queue>"))
        snapshot.add_transformer(snapshot.transform.s3_notifications_transformer())
        snapshot.add_transformer(snapshot.transform.sns_api())

        # connect topic to queue
        sns_create_sqs_subscription(topic_arn, queue_url)
        create_sns_bucket_notification(
            aws_client.s3, aws_client.sns, s3_bucket, topic_arn, ["s3:ObjectCreated:*"]
        )
        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "TopicConfigurations": [
                    {
                        "Id": "id123",
                        "Events": ["s3:ObjectCreated:*"],
                        "TopicArn": topic_arn,
                        "Filter": {
                            "Key": {"FilterRules": [{"Name": "Prefix", "Value": "testupload/"}]}
                        },
                    }
                ]
            },
        )
        test_key1 = "test/dir1/myfile.txt"
        test_key2 = "testupload/dir1/testfile.txt"
        test_data = b'{"test": "bucket_notification one"}'

        aws_client.s3.upload_fileobj(BytesIO(test_data), s3_bucket, test_key1)
        aws_client.s3.upload_fileobj(BytesIO(test_data), s3_bucket, test_key2)

        messages = sqs_collect_sns_messages(aws_client.sqs, queue_url, 1)
        assert len(messages) == 1
        snapshot.match("message", messages[0])
        message = messages[0]
        assert message["Type"] == "Notification"
        assert message["TopicArn"] == topic_arn
        assert message["Subject"] == "Amazon S3 Notification"

        event = json.loads(message["Message"])["Records"][0]
        assert event["eventSource"] == "aws:s3"
        assert event["eventName"] == "ObjectCreated:Put"
        assert event["s3"]["bucket"]["name"] == s3_bucket
        assert event["s3"]["object"]["key"] == test_key2

    @markers.aws.validated
    def test_bucket_not_exist(self, account_id, region_name, snapshot, aws_client):
        bucket_name = f"this-bucket-does-not-exist-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.s3_api())
        config = {
            "TopicConfigurations": [
                {
                    "Id": "id123",
                    "Events": ["s3:ObjectCreated:*"],
                    "TopicArn": f"{arns.sns_topic_arn('my-topic', account_id=account_id, region_name=region_name)}",
                }
            ]
        }

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
                SkipDestinationValidation=True,
            )
        snapshot.match("bucket_not_exists", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Error.ArgumentName", "$..Error.ArgumentValue"],
    )
    def test_invalid_topic_arn(self, s3_bucket, account_id, region_name, snapshot, aws_client):
        config = {
            "TopicConfigurations": [
                {
                    "Id": "id123",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        }

        config["TopicConfigurations"][0]["TopicArn"] = "invalid-topic"
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
                SkipDestinationValidation=False,
            )
        snapshot.match("invalid_not_skip", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
                SkipDestinationValidation=True,
            )
        snapshot.match("invalid_skip", e.value.response)

        # set valid but not-existing topic
        config["TopicConfigurations"][0]["TopicArn"] = (
            f"{arns.sns_topic_arn('my-topic', account_id=account_id, region_name=region_name)}"
        )
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
            )
        # TODO cannot snapshot as AWS seems to check permission first -> as it does not exist, we cannot set permissions here
        assert e.match("InvalidArgument")

        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration=config, SkipDestinationValidation=True
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("skip_destination_validation", config)
