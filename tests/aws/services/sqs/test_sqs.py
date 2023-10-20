import json
import os
import re
import time
from threading import Timer
from typing import Dict

import pytest
import requests
from botocore.exceptions import ClientError

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import (
    DEFAULT_AWS_ACCOUNT_ID,
    SECONDARY_TEST_AWS_ACCESS_KEY_ID,
    SECONDARY_TEST_AWS_ACCOUNT_ID,
    SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_ACCOUNT_ID,
    TEST_AWS_REGION_NAME,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.services.sqs.constants import DEFAULT_MAXIMUM_MESSAGE_SIZE
from localstack.services.sqs.models import sqs_stores
from localstack.services.sqs.provider import MAX_NUMBER_OF_MESSAGES
from localstack.services.sqs.utils import parse_queue_url
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer import GenericTransformer
from localstack.utils.aws import arns, aws_stack
from localstack.utils.common import poll_condition, retry, short_uid, to_str
from tests.aws.services.lambda_.functions import lambda_integration
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON

TEST_POLICY = """
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect": "Allow",
      "Principal": { "AWS": "*" },
      "Action": "sqs:SendMessage",
      "Resource": "'$sqs_queue_arn'",
      "Condition":{
        "ArnEquals":{
        "aws:SourceArn":"'$sns_topic_arn'"
        }
      }
    }
  ]
}
"""


def get_qsize(sqs_client, queue_url: str) -> int:
    """
    Returns the integer value of the ApproximateNumberOfMessages queue attribute.

    :param sqs_client: the boto3 client
    :param queue_url: the queue URL
    :return: the ApproximateNumberOfMessages converted to int
    """
    response = sqs_client.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
    )
    return int(response["Attributes"]["ApproximateNumberOfMessages"])


@pytest.fixture(autouse=True)
def sqs_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.sqs_api())


class TestSqsProvider:
    @markers.aws.only_localstack
    def test_get_queue_url_contains_request_host(
        self, sqs_create_queue, monkeypatch, aws_client, aws_client_factory
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")

        queue_name = "test-queue-" + short_uid()

        sqs_create_queue(QueueName=queue_name)

        queue_url = aws_client.sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]

        host = config.get_edge_url()
        # our current queue pattern looks like this, but may change going forward, or may be configurable
        assert queue_url == f"{host}/{TEST_AWS_ACCOUNT_ID}/{queue_name}"

        # attempt to connect through a different host and make sure the URL contains that host
        host = f"http://127.0.0.1:{config.EDGE_PORT}"
        client = aws_client_factory(endpoint_url=host).sqs
        queue_url = client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        assert queue_url == f"{host}/{TEST_AWS_ACCOUNT_ID}/{queue_name}"

    @markers.aws.validated
    def test_list_queues(self, sqs_create_queue, aws_client):
        queue_names = [
            "a-test-queue-" + short_uid(),
            "a-test-queue-" + short_uid(),
            "b-test-queue-" + short_uid(),
        ]

        # create three queues with prefixes and collect their urls
        queue_urls = []
        for name in queue_names:
            sqs_create_queue(QueueName=name)
            queue_url = aws_client.sqs.get_queue_url(QueueName=name)["QueueUrl"]
            assert queue_url.endswith(name)
            queue_urls.append(queue_url)

        # list queues with first prefix
        result = aws_client.sqs.list_queues(QueueNamePrefix="a-test-queue-")
        assert "QueueUrls" in result
        assert len(result["QueueUrls"]) == 2
        assert queue_urls[0] in result["QueueUrls"]
        assert queue_urls[1] in result["QueueUrls"]
        assert queue_urls[2] not in result["QueueUrls"]

        # list queues with second prefix
        result = aws_client.sqs.list_queues(QueueNamePrefix="b-test-queue-")
        assert "QueueUrls" in result
        assert len(result["QueueUrls"]) == 1
        assert queue_urls[0] not in result["QueueUrls"]
        assert queue_urls[1] not in result["QueueUrls"]
        assert queue_urls[2] in result["QueueUrls"]

        # list queues regardless of prefix prefix
        result = aws_client.sqs.list_queues()
        assert "QueueUrls" in result
        for url in queue_urls:
            assert url in result["QueueUrls"]

    @markers.aws.validated
    def test_create_queue_and_get_attributes(self, sqs_queue, aws_client):
        result = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["QueueArn", "CreatedTimestamp", "VisibilityTimeout"]
        )
        assert "Attributes" in result

        attrs = result["Attributes"]
        assert len(attrs) == 3
        assert "test-queue-" in attrs["QueueArn"]
        assert int(float(attrs["CreatedTimestamp"])) == pytest.approx(int(time.time()), 30)
        assert int(attrs["VisibilityTimeout"]) == 30, "visibility timeout is not the default value"

    @markers.aws.validated
    def test_create_queue_recently_deleted(self, sqs_create_queue, monkeypatch, aws_client):
        monkeypatch.setattr(config, "SQS_DELAY_RECENTLY_DELETED", True)

        name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=name)
        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        with pytest.raises(ClientError) as e:
            sqs_create_queue(QueueName=name)

        e.match("QueueDeletedRecently")
        e.match(
            "You must wait 60 seconds after deleting a queue before you can create another with the same name."
        )

    @markers.aws.only_localstack
    def test_create_queue_recently_deleted_cache(self, sqs_create_queue, monkeypatch, aws_client):
        # this is a white-box test for the QueueDeletedRecently timeout behavior
        from localstack.services.sqs import constants

        monkeypatch.setattr(config, "SQS_DELAY_RECENTLY_DELETED", True)
        monkeypatch.setattr(constants, "RECENTLY_DELETED_TIMEOUT", 1)

        name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=name)
        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        with pytest.raises(ClientError) as e:
            sqs_create_queue(QueueName=name)

        e.match("QueueDeletedRecently")
        e.match(
            "You must wait 60 seconds after deleting a queue before you can create another with the same name."
        )

        time.sleep(1.5)
        store = sqs_stores[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME]
        assert name in store.deleted
        assert queue_url == sqs_create_queue(QueueName=name)
        assert name not in store.deleted

    @markers.aws.only_localstack
    def test_create_queue_recently_deleted_can_be_disabled(
        self, sqs_create_queue, monkeypatch, aws_client
    ):
        monkeypatch.setattr(config, "SQS_DELAY_RECENTLY_DELETED", False)

        name = f"test-queue-{short_uid()}"

        queue_url = sqs_create_queue(QueueName=name)
        aws_client.sqs.delete_queue(QueueUrl=queue_url)
        assert queue_url == sqs_create_queue(QueueName=name)

    @markers.aws.validated
    def test_send_receive_message(self, sqs_queue, aws_client):
        send_result = aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="message")

        assert send_result["MessageId"]
        assert send_result["MD5OfMessageBody"] == "78e731027d8fd50ed642340b7c9a63b3"
        # TODO: other attributes

        receive_result = aws_client.sqs.receive_message(QueueUrl=sqs_queue)

        assert len(receive_result["Messages"]) == 1
        message = receive_result["Messages"][0]

        assert message["ReceiptHandle"]
        assert message["Body"] == "message"
        assert message["MessageId"] == send_result["MessageId"]
        assert message["MD5OfBody"] == send_result["MD5OfMessageBody"]

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_receive_max_number_of_messages(self, sqs_queue, snapshot, aws_client):
        queue_url = sqs_queue
        send_result = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message")
        assert send_result["MessageId"]

        with pytest.raises(ClientError) as e:
            aws_client.sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=MAX_NUMBER_OF_MESSAGES + 1
            )

        snapshot.match("send_max_number_of_messages", e.value.response)

    @markers.aws.validated
    def test_receive_message_attributes_timestamp_types(self, sqs_queue, aws_client):
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="message")

        r0 = aws_client.sqs.receive_message(
            QueueUrl=sqs_queue, VisibilityTimeout=0, AttributeNames=["All"]
        )
        attrs = r0["Messages"][0]["Attributes"]
        assert float(attrs["ApproximateFirstReceiveTimestamp"]).is_integer()
        assert float(attrs["SentTimestamp"]).is_integer()

        assert float(attrs["SentTimestamp"]) == pytest.approx(
            float(attrs["ApproximateFirstReceiveTimestamp"]), 2
        )

    @markers.aws.validated
    def test_send_receive_message_multiple_queues(self, sqs_create_queue, aws_client):
        queue0 = sqs_create_queue()
        queue1 = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue0, MessageBody="message")

        result = aws_client.sqs.receive_message(QueueUrl=queue1)
        assert "Messages" not in result

        result = aws_client.sqs.receive_message(QueueUrl=queue0)
        assert len(result["Messages"]) == 1
        assert result["Messages"][0]["Body"] == "message"

    @markers.aws.validated
    def test_send_receive_message_encoded_content(self, sqs_create_queue, aws_client):
        queue = sqs_create_queue()
        aws_client.sqs.send_message(QueueUrl=queue, MessageBody='"&quot;&quot;\r')
        result = aws_client.sqs.receive_message(QueueUrl=queue)
        assert len(result["Messages"]) == 1
        assert result["Messages"][0]["Body"] == '"&quot;&quot;\r'

    @markers.aws.validated
    def test_send_message_batch(self, sqs_queue, aws_client):
        aws_client.sqs.send_message_batch(
            QueueUrl=sqs_queue,
            Entries=[
                {"Id": "1", "MessageBody": "message-0"},
                {"Id": "2", "MessageBody": "message-1"},
            ],
        )

        response0 = aws_client.sqs.receive_message(QueueUrl=sqs_queue)
        response1 = aws_client.sqs.receive_message(QueueUrl=sqs_queue)
        response2 = aws_client.sqs.receive_message(QueueUrl=sqs_queue)

        assert len(response0.get("Messages", [])) == 1
        assert len(response1.get("Messages", [])) == 1
        assert len(response2.get("Messages", [])) == 0

        message0 = response0["Messages"][0]
        message1 = response1["Messages"][0]

        assert message0["Body"] == "message-0"
        assert message1["Body"] == "message-1"

    @markers.aws.validated
    def test_send_batch_receive_multiple(self, sqs_queue, aws_client):
        # send a batch, then a single message, then receive them
        # Important: AWS does not guarantee the order of messages, be it within the batch or between sends
        message_count = 3
        aws_client.sqs.send_message_batch(
            QueueUrl=sqs_queue,
            Entries=[
                {"Id": "1", "MessageBody": "message-0"},
                {"Id": "2", "MessageBody": "message-1"},
            ],
        )
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="message-2")
        i = 0
        result_recv = {"Messages": []}
        while len(result_recv["Messages"]) < message_count and i < message_count:
            result_recv["Messages"] = result_recv["Messages"] + (
                aws_client.sqs.receive_message(
                    QueueUrl=sqs_queue, MaxNumberOfMessages=message_count
                ).get("Messages")
            )
            i += 1
        assert len(result_recv["Messages"]) == message_count
        assert set(result_recv["Messages"][b]["Body"] for b in range(message_count)) == set(
            f"message-{b}" for b in range(message_count)
        )

    @markers.aws.validated
    def test_send_message_batch_with_empty_list(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        try:
            aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=[])
        except ClientError as e:
            assert "EmptyBatchRequest" in e.response["Error"]["Code"]
            assert e.response["ResponseMetadata"]["HTTPStatusCode"] in [400, 404]

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_oversized_message(self, sqs_queue, snapshot, aws_client):
        with pytest.raises(ClientError) as e:
            message_attributes = {"k": {"DataType": "String", "StringValue": "x"}}
            message_attributes_size = len("k") + len("String") + len("x")
            message_body = "a" * (DEFAULT_MAXIMUM_MESSAGE_SIZE - message_attributes_size + 1)
            aws_client.sqs.send_message(
                QueueUrl=sqs_queue,
                MessageBody=message_body,
                MessageAttributes=message_attributes,
            )

        snapshot.match("send_oversized_message", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_message_with_updated_maximum_message_size(self, sqs_queue, snapshot, aws_client):
        new_max_message_size = 1024
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue,
            Attributes={"MaximumMessageSize": str(new_max_message_size)},
        )

        # check base case still works
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="a" * new_max_message_size)

        # check error case
        with pytest.raises(ClientError) as e:
            message_attributes = {"k": {"DataType": "String", "StringValue": "x"}}
            message_attributes_size = len("k") + len("String") + len("x")
            message_body = "a" * (new_max_message_size - message_attributes_size + 1)
            aws_client.sqs.send_message(
                QueueUrl=sqs_queue,
                MessageBody=message_body,
                MessageAttributes=message_attributes,
            )

        snapshot.match("send_oversized_message", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_message_batch_with_oversized_contents(self, sqs_queue, snapshot, aws_client):
        # Send two messages, one of max message size and a second with
        # message body of size 1
        with pytest.raises(ClientError) as e:
            message_attributes = {"k": {"DataType": "String", "StringValue": "x"}}
            message_attributes_size = len("k") + len("String") + len("x")
            message_body = "a" * (DEFAULT_MAXIMUM_MESSAGE_SIZE - message_attributes_size)
            aws_client.sqs.send_message_batch(
                QueueUrl=sqs_queue,
                Entries=[
                    {
                        "Id": "1",
                        "MessageBody": message_body,
                        "MessageAttributes": message_attributes,
                    },
                    {"Id": "2", "MessageBody": "a"},
                ],
            )

        snapshot.match("send_oversized_message_batch", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_message_batch_with_oversized_contents_with_updated_maximum_message_size(
        self, sqs_queue, snapshot, aws_client
    ):
        new_max_message_size = 2048
        aws_client.sqs.set_queue_attributes(
            QueueUrl=sqs_queue,
            Attributes={"MaximumMessageSize": str(new_max_message_size)},
        )

        # batch send seems to ignore the MaximumMessageSize of the queue
        message_attributes = {"k": {"DataType": "String", "StringValue": "x"}}
        message_attributes_size = len("k") + len("String") + len("x")
        message_body = "a" * (new_max_message_size - message_attributes_size)
        response = aws_client.sqs.send_message_batch(
            QueueUrl=sqs_queue,
            Entries=[
                {"Id": "1", "MessageBody": message_body, "MessageAttributes": message_attributes},
                {"Id": "2", "MessageBody": "a"},
            ],
        )

        snapshot.match("send_oversized_message_batch", response)

    @markers.aws.validated
    def test_tag_untag_queue(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2", "tag3": ""}
        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)

        # check queue tags
        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

        # remove tag1 and tag3
        aws_client.sqs.untag_queue(QueueUrl=queue_url, TagKeys=["tag1", "tag3"])
        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag2": "value2"}

        # remove tag2
        aws_client.sqs.untag_queue(QueueUrl=queue_url, TagKeys=["tag2"])

        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert "Tags" not in response

    @markers.aws.validated
    def test_tags_case_sensitive(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"MyTag": "value1", "mytag": "value2"}
        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)

        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

    @markers.aws.validated
    def test_untag_queue_ignores_non_existing_tag(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2"}
        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)

        # remove tags
        aws_client.sqs.untag_queue(QueueUrl=queue_url, TagKeys=["tag1", "tag3"])

        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag2": "value2"}

    @markers.aws.validated
    def test_tag_queue_overwrites_existing_tag(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2"}
        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)

        # overwrite tags
        tags = {"tag1": "VALUE1", "tag3": "value3"}
        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)

        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag1": "VALUE1", "tag2": "value2", "tag3": "value3"}

    @markers.aws.validated
    def test_create_queue_with_tags(self, sqs_create_queue, aws_client):
        tags = {"tag1": "value1", "tag2": "value2"}
        queue_url = sqs_create_queue(tags=tags)

        response = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

    @markers.aws.validated
    def test_create_queue_without_attributes_is_idempotent(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"

        queue_url = sqs_create_queue(QueueName=queue_name)

        assert sqs_create_queue(QueueName=queue_name) == queue_url

    @markers.aws.validated
    def test_create_queue_with_same_attributes_is_idempotent(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        attributes = {
            "VisibilityTimeout": "69",
        }

        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        assert sqs_create_queue(QueueName=queue_name, Attributes=attributes) == queue_url

    @markers.aws.validated
    def test_receive_message_wait_time_seconds_and_max_number_of_messages_does_not_block(
        self, sqs_create_queue, aws_client
    ):
        """
        this test makes sure that `WaitTimeSeconds` does not block when messages are in the queue, even when
        `MaxNumberOfMessages` is provided.
        """
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar2")

        # wait for the two messages to be in the queue
        assert poll_condition(lambda: get_qsize(aws_client.sqs, queue_url) == 2, timeout=10)

        then = time.time()
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=3, WaitTimeSeconds=5
        )
        took = time.time() - then
        assert took < 2  # should take much less than 5 seconds

        assert (
            len(response.get("Messages", [])) >= 1
        ), f"unexpected number of messages in {response}"

    @markers.aws.validated
    def test_wait_time_seconds_waits_correctly(self, sqs_queue, aws_client):
        def _send_message():
            aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="foobared")

        Timer(1, _send_message).start()  # send message asynchronously after 1 second
        response = aws_client.sqs.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=10)

        assert (
            len(response.get("Messages", [])) == 1
        ), f"unexpected number of messages in response {response}"

    @markers.aws.validated
    def test_wait_time_seconds_queue_attribute_waits_correctly(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(
            Attributes={
                "ReceiveMessageWaitTimeSeconds": "10",
            }
        )

        def _send_message():
            aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobared")

        Timer(1, _send_message).start()  # send message asynchronously after 1 second
        response = aws_client.sqs.receive_message(QueueUrl=queue_url)

        assert (
            len(response.get("Messages", [])) == 1
        ), f"unexpected number of messages in response {response}"

    @markers.aws.validated
    def test_create_queue_with_default_attributes_is_idempotent(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        attributes = {
            "VisibilityTimeout": "69",
            "ReceiveMessageWaitTimeSeconds": "1",
        }

        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        assert sqs_create_queue(QueueName=queue_name) == queue_url

    @markers.aws.validated
    def test_create_fifo_queue_with_same_attributes_is_idempotent(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {"FifoQueue": "true"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        assert sqs_create_queue(QueueName=queue_name, Attributes=attributes) == queue_url

    @markers.aws.validated
    def test_create_fifo_queue_with_different_attributes_raises_error(
        self, sqs_create_queue, aws_client
    ):
        queue_name = f"queue-{short_uid()}.fifo"
        sqs_create_queue(
            QueueName=queue_name,
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )
        with pytest.raises(aws_client.sqs.exceptions.QueueNameExists):
            sqs_create_queue(
                QueueName=queue_name,
                Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "false"},
            )

    @markers.aws.validated
    def test_send_message_with_delay_0_works_for_fifo(self, sqs_create_queue, aws_client):
        # see issue https://github.com/localstack/localstack/issues/6612
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {"FifoQueue": "true"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        message_sent_hash = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            DelaySeconds=0,
            MessageBody="Hello World!",
            MessageGroupId="test",
            MessageDeduplicationId="42",
        )["MD5OfMessageBody"]
        message_received_hash = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0
        )["Messages"][0]["MD5OfBody"]
        assert message_sent_hash == message_received_hash

    @markers.aws.validated
    def test_create_queue_with_different_attributes_raises_exception(
        self, sqs_create_queue, snapshot, aws_client
    ):
        queue_name = f"queue-{short_uid()}"

        # create queue with ReceiveMessageWaitTimeSeconds=2
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "ReceiveMessageWaitTimeSeconds": "1",
                "DelaySeconds": "1",
            },
        )

        # try to create a queue without attributes works
        assert queue_url == sqs_create_queue(QueueName=queue_name)

        # try to create a queue with one attribute specified
        assert queue_url == sqs_create_queue(QueueName=queue_name, Attributes={"DelaySeconds": "1"})

        # try to create a queue with the same name but different ReceiveMessageWaitTimeSeconds value
        with pytest.raises(ClientError) as e:
            sqs_create_queue(
                QueueName=queue_name,
                Attributes={
                    "ReceiveMessageWaitTimeSeconds": "1",
                    "DelaySeconds": "2",
                },
            )
        snapshot.match("create_queue_01", e.value)

        # update the attribute of the queue
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"DelaySeconds": "2"})

        # try again
        assert queue_url == sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "ReceiveMessageWaitTimeSeconds": "1",
                "DelaySeconds": "2",
            },
        )

        # try with the original request
        with pytest.raises(ClientError) as e:
            sqs_create_queue(
                QueueName=queue_name,
                Attributes={
                    "ReceiveMessageWaitTimeSeconds": "1",
                    "DelaySeconds": "1",
                },
            )
        snapshot.match("create_queue_02", e.value)

    @markers.aws.validated
    def test_create_queue_after_internal_attributes_changes_works(
        self, sqs_create_queue, aws_client
    ):
        queue_name = f"queue-{short_uid()}"

        queue_url = sqs_create_queue(QueueName=queue_name)

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar-1", DelaySeconds=1)
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar-2")

        assert queue_url == sqs_create_queue(QueueName=queue_name)

    @markers.aws.validated
    def test_create_and_update_queue_attributes(self, sqs_create_queue, snapshot, aws_client):
        queue_url = sqs_create_queue(
            Attributes={
                "MessageRetentionPeriod": "604800",  # Unsupported by ElasticMq, should be saved in memory
                "ReceiveMessageWaitTimeSeconds": "10",
                "VisibilityTimeout": "20",
            }
        )

        response = aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        snapshot.match("get_queue_attributes", response)

        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "MaximumMessageSize": "2048",
                "VisibilityTimeout": "69",
                "DelaySeconds": "420",
            },
        )

        response = aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        snapshot.match("get_updated_queue_attributes", response)

    @markers.aws.validated
    @pytest.mark.xfail(reason="see https://github.com/localstack/localstack/issues/5938")
    def test_create_queue_with_default_arguments_works_with_modified_attributes(
        self, sqs_create_queue, aws_client
    ):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "VisibilityTimeout": "2",
                "ReceiveMessageWaitTimeSeconds": "2",
            },
        )

        # original attributes
        with pytest.raises(ClientError) as e:
            sqs_create_queue(
                QueueName=queue_name,
                Attributes={
                    "VisibilityTimeout": "1",
                    "ReceiveMessageWaitTimeSeconds": "1",
                },
            )
        e.match("QueueAlreadyExists")

        # modified attributes
        assert queue_url == sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "2",
                "ReceiveMessageWaitTimeSeconds": "2",
            },
        )

        # no attributes always works
        assert queue_url == sqs_create_queue(QueueName=queue_name)

    @markers.aws.validated
    @pytest.mark.xfail(reason="see https://github.com/localstack/localstack/issues/5938")
    def test_create_queue_after_modified_attributes(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "1",
                "ReceiveMessageWaitTimeSeconds": "1",
            },
        )

        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={
                "VisibilityTimeout": "2",
                "ReceiveMessageWaitTimeSeconds": "2",
            },
        )

        # original attributes
        with pytest.raises(ClientError) as e:
            sqs_create_queue(
                QueueName=queue_name,
                Attributes={
                    "VisibilityTimeout": "1",
                    "ReceiveMessageWaitTimeSeconds": "1",
                },
            )
        e.match("QueueAlreadyExists")

        # modified attributes
        assert queue_url == sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "VisibilityTimeout": "2",
                "ReceiveMessageWaitTimeSeconds": "2",
            },
        )

        # no attributes always works
        assert queue_url == sqs_create_queue(QueueName=queue_name)

    @markers.aws.validated
    def test_create_queue_after_send(self, sqs_create_queue, aws_client):
        # checks that intrinsic queue attributes like "ApproxMessages" does not hinder queue creation
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="bared")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="baz")

        def _qsize(_url):
            response = aws_client.sqs.get_queue_attributes(
                QueueUrl=_url, AttributeNames=["ApproximateNumberOfMessages"]
            )
            return int(response["Attributes"]["ApproximateNumberOfMessages"])

        assert poll_condition(lambda: _qsize(queue_url) > 0, timeout=10)

        # we know that the system attribute has changed, now check whether create_queue works
        assert queue_url == sqs_create_queue(QueueName=queue_name)

    @markers.aws.validated
    def test_send_delay_and_wait_time(self, sqs_queue, aws_client):
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="foobar", DelaySeconds=1)

        result = aws_client.sqs.receive_message(QueueUrl=sqs_queue)
        assert "Messages" not in result

        result = aws_client.sqs.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=2)
        assert "Messages" in result
        assert len(result["Messages"]) == 1

    @markers.aws.only_localstack
    def test_approximate_number_of_messages_delayed(self, sqs_queue, aws_client):
        # this test does not work against AWS in the same way, because AWS only has eventual consistency guarantees
        # for the tested attributes that can take up to a minute to update.
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="ed")
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="foo", DelaySeconds=2)
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="bar", DelaySeconds=2)

        result = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue,
            AttributeNames=[
                "ApproximateNumberOfMessages",
                "ApproximateNumberOfMessagesNotVisible",
                "ApproximateNumberOfMessagesDelayed",
            ],
        )
        assert result["Attributes"] == {
            "ApproximateNumberOfMessages": "1",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "ApproximateNumberOfMessagesDelayed": "2",
        }

        def _assert():
            _result = aws_client.sqs.get_queue_attributes(
                QueueUrl=sqs_queue,
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "ApproximateNumberOfMessagesDelayed",
                ],
            )
            assert _result["Attributes"] == {
                "ApproximateNumberOfMessages": "3",
                "ApproximateNumberOfMessagesNotVisible": "0",
                "ApproximateNumberOfMessagesDelayed": "0",
            }

        retry(_assert)

    @markers.aws.validated
    def test_receive_after_visibility_timeout(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(Attributes={"VisibilityTimeout": "1"})

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar")

        # receive the message
        result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" in result
        message_receipt_0 = result["Messages"][0]

        # message should be within the visibility timeout
        result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result

        # visibility timeout should have expired
        result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)
        assert "Messages" in result
        message_receipt_1 = result["Messages"][0]

        assert (
            message_receipt_0["ReceiptHandle"] != message_receipt_1["ReceiptHandle"]
        ), "receipt handles should be different"

    @markers.aws.validated
    def test_receive_terminate_visibility_timeout(self, sqs_queue, aws_client):
        queue_url = sqs_queue

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="foobar")

        result = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
        assert "Messages" in result
        message_receipt_0 = result["Messages"][0]

        result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" in result
        message_receipt_1 = result["Messages"][0]

        assert (
            message_receipt_0["ReceiptHandle"] != message_receipt_1["ReceiptHandle"]
        ), "receipt handles should be different"

        # TODO: check if this is correct (whether receive with VisibilityTimeout = 0 is permanent)
        result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result

    @markers.aws.validated
    def test_extend_message_visibility_timeout_set_in_queue(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(Attributes={"VisibilityTimeout": "2"})

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)
        receipt = response["Messages"][0]["ReceiptHandle"]

        # update even if time expires
        for _ in range(4):
            time.sleep(1)
            # we've waited a total of four seconds, although the visibility timeout is 2, so we are extending it
            aws_client.sqs.change_message_visibility(
                QueueUrl=queue_url, ReceiptHandle=receipt, VisibilityTimeout=2
            )
            assert aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages", []) == []

        messages = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=5)["Messages"]
        assert messages[0]["Body"] == "test"
        assert len(messages) == 1

    @markers.aws.validated
    def test_receive_message_with_visibility_timeout_updates_timeout(
        self, sqs_create_queue, aws_client
    ):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=2, VisibilityTimeout=0
        )
        assert len(response["Messages"]) == 1

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=3)
        assert len(response["Messages"]) == 1

        response = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert response.get("Messages", []) == []

    @markers.aws.validated
    def test_terminate_visibility_timeout_after_receive(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=2, VisibilityTimeout=0
        )
        receipt_1 = response["Messages"][0]["ReceiptHandle"]
        assert len(response["Messages"]) == 1

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=3)
        assert len(response["Messages"]) == 1

        aws_client.sqs.change_message_visibility(
            QueueUrl=queue_url, ReceiptHandle=receipt_1, VisibilityTimeout=0
        )
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
        assert len(response["Messages"]) == 1

    @markers.aws.needs_fixing
    def test_delete_message_batch_from_lambda(
        self, sqs_create_queue, create_lambda_function, aws_client
    ):
        # issue 3671 - not recreatable
        # TODO: lambda creation does not work when testing against AWS
        queue_url = sqs_create_queue()

        lambda_name = f"lambda-{short_uid()}"
        create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_9,
        )
        delete_batch_payload = {lambda_integration.MSG_BODY_DELETE_BATCH: queue_url}
        batch = []
        for i in range(4):
            batch.append({"Id": str(i), "MessageBody": str(i)})
        aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=batch)

        aws_client.lambda_.invoke(
            FunctionName=lambda_name, Payload=json.dumps(delete_batch_payload), LogType="Tail"
        )

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in receive_result.keys()

    @markers.aws.validated
    def test_invalid_receipt_handle_should_return_error_message(self, sqs_create_queue, aws_client):
        # issue 3619
        queue_url = sqs_create_queue()
        with pytest.raises(Exception) as e:
            aws_client.sqs.change_message_visibility(
                QueueUrl=queue_url, ReceiptHandle="INVALID", VisibilityTimeout=60
            )
        e.match("ReceiptHandleIsInvalid")

    @markers.aws.validated
    def test_message_with_attributes_should_be_enqueued(self, sqs_create_queue, aws_client):
        # issue 3737
        queue_url = sqs_create_queue()

        message_body = "test"
        timestamp_attribute = {"DataType": "Number", "StringValue": "1614717034367"}
        message_attributes = {"timestamp": timestamp_attribute}
        response_send = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=message_body, MessageAttributes=message_attributes
        )
        response_receive = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        message = response_receive["Messages"][0]
        assert message["MessageId"] == response_send["MessageId"]
        assert message["MessageAttributes"] == message_attributes

    @markers.aws.validated
    def test_batch_send_with_invalid_char_should_succeed(self, sqs_create_queue, aws_client):
        # issue 4135
        queue_url = sqs_create_queue()

        batch = []
        for i in range(0, 9):
            batch.append({"Id": str(i), "MessageBody": str(i)})
        batch.append({"Id": "9", "MessageBody": "\x01"})

        result_send = aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=batch)

        # check the one failed message
        assert len(result_send["Failed"]) == 1
        failed = result_send["Failed"][0]
        assert failed["Id"] == "9"
        assert failed["Code"] == "InvalidMessageContents"

        # check successful message bodies
        messages = []

        def collect_messages():
            response = aws_client.sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            )
            messages.extend(response.get("Messages", []))
            return len(messages)

        assert poll_condition(
            lambda: collect_messages() >= 9, timeout=10
        ), f"gave up waiting messages, got {len(messages)} from 9"

        bodies = {message["Body"] for message in messages}
        assert bodies == {"0", "1", "2", "3", "4", "5", "6", "7", "8"}

    @markers.aws.only_localstack
    def test_external_hostname(self, monkeypatch, sqs_create_queue, aws_client):
        external_host = "external-host"
        external_port = "12345"

        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")
        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)
        monkeypatch.setattr(config, "HOSTNAME_EXTERNAL", external_host)

        queue_url = sqs_create_queue()

        assert f"{external_host}:{external_port}" in queue_url

        message_body = "external_host_test"
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert receive_result["Messages"][0]["Body"] == message_body

    @markers.aws.only_localstack
    def test_external_hostname_via_host_header(self, monkeypatch, sqs_create_queue):
        """test making a request with a different external hostname/port being returned"""
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")

        queue_name = f"queue-{short_uid()}"
        sqs_create_queue(QueueName=queue_name)

        edge_url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers("sqs")
        payload = f"Action=GetQueueUrl&QueueName={queue_name}"

        # assert regular/default queue URL is returned
        url = f"{edge_url}"
        result = requests.post(url, data=payload, headers=headers)
        assert result
        content = to_str(result.content)
        kwargs = {"flags": re.MULTILINE | re.DOTALL}
        assert re.match(rf".*<QueueUrl>\s*{edge_url}/[^<]+</QueueUrl>.*", content, **kwargs)

        # assert custom port is returned in queue URL
        port = 12345
        headers["Host"] = f"local-test-host:{port}"
        result = requests.post(url, data=payload, headers=headers)
        assert result
        content = to_str(result.content)
        # TODO: currently only asserting that the port matches - potentially should also return the custom hostname?
        assert re.match(rf".*<QueueUrl>\s*http://[^:]+:{port}[^<]+</QueueUrl>.*", content, **kwargs)

    @markers.aws.only_localstack
    def test_external_host_via_header_complete_message_lifecycle(self, monkeypatch):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")

        queue_name = f"queue-{short_uid()}"

        edge_url = config.get_edge_url()
        headers = aws_stack.mock_aws_request_headers("sqs")
        port = 12345
        hostname = "aws-local"

        url = f"{hostname}:{port}"
        headers["Host"] = url
        payload = f"Action=CreateQueue&QueueName={queue_name}"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert url in result.text

        queue_url = f"http://{url}/{TEST_AWS_ACCOUNT_ID}/{queue_name}"
        message_body = f"test message {short_uid()}"
        payload = f"Action=SendMessage&QueueUrl={queue_url}&MessageBody={message_body}"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert "MD5" in result.text

        payload = f"Action=ReceiveMessage&QueueUrl={queue_url}&VisibilityTimeout=0"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert message_body in result.text

        # the customer said that he used to be able to access it via "127.0.0.1" instead of "aws-local" as well
        queue_url = f"http://127.0.0.1/{TEST_AWS_ACCOUNT_ID}/{queue_name}"

        payload = f"Action=SendMessage&QueueUrl={queue_url}&MessageBody={message_body}"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert "MD5" in result.text

        queue_url = f"http://127.0.0.1/{TEST_AWS_ACCOUNT_ID}/{queue_name}"

        payload = f"Action=ReceiveMessage&QueueUrl={queue_url}&VisibilityTimeout=0"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert message_body in result.text

    @markers.aws.validated
    def test_fifo_messages_in_order_after_timeout(self, sqs_create_queue, aws_client):
        # issue 4287
        queue_name = f"queue-{short_uid()}.fifo"
        timeout = 1
        attributes = {"FifoQueue": "true", "VisibilityTimeout": f"{timeout}"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        for i in range(3):
            aws_client.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=f"message-{i}",
                MessageGroupId="1",
                MessageDeduplicationId=f"{i}",
            )

        def receive_and_check_order():
            result_receive = aws_client.sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=10
            )
            for j in range(3):
                assert result_receive["Messages"][j]["Body"] == f"message-{j}"

        receive_and_check_order()
        time.sleep(timeout + 1)
        receive_and_check_order()

    @markers.aws.validated
    def test_fifo_receive_message_group_id_ordering(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        # add message to group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        # we interleave one message in group 2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )
        # and then continue with group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m3", MessageGroupId="group-1"
        )

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)

        # even though we sent a message from group 2 in between messages of group 1, the messages arrive in
        # order of the message groups
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"
        assert response["Messages"][2]["Body"] == "g1-m3"
        assert response["Messages"][3]["Body"] == "g2-m1"

    @markers.aws.validated
    def test_fifo_receive_message_visibility_timeout_shared_in_group(
        self, sqs_create_queue, aws_client
    ):
        timeout = 1
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "VisibilityTimeout": f"{timeout}",
                "ContentBasedDeduplication": "true",
            },
        )

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m3", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m4", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g3-m1", MessageGroupId="group-3"
        )

        # we receive 2 messages of the 3 in the first message group
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"

        # the entire group 1 is affected by the visibility timeout, so the next receive returns a message
        # of group 2
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        assert response["Messages"][0]["Body"] == "g2-m1"

        # let the visibility timeout expire
        time.sleep(timeout + 1)

        # now we try to fetch all messages from the queue. since there are no guarantees about the ordering of
        # message groups themselves, multiple orderings are valid now
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, VisibilityTimeout=0
        )
        ordering = [message["Body"] for message in response["Messages"]]
        # there's a race that can cause both orderings to happen, but both are valid
        assert ordering in (
            ["g3-m1", "g1-m1", "g1-m2", "g1-m3", "g1-m4", "g2-m1"],  # aws and localstack
            ["g3-m1", "g2-m1", "g1-m1", "g1-m2", "g1-m3", "g1-m4"],  # localstack
        )

    @markers.aws.validated
    def test_fifo_receive_message_with_zero_visibility_timeout(self, sqs_create_queue, aws_client):
        # this test shows that receiving messages from a fifo queue with visibility timeout = 0 terminates the
        # group's visibility correctly.
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        # interleave g2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )
        # interleave g2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m2", MessageGroupId="group-2"
        )
        # interleave g3
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g3-m1", MessageGroupId="group-3"
        )
        # send another message to g1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )

        # we receive messages from the first two groups with a visibility timeout of 0, ordering is preserved
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=3, VisibilityTimeout=0
        )
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"
        assert response["Messages"][2]["Body"] == "g2-m1"

        # now we try to fetch all messages from the queue. since there are no guarantees about the ordering of
        # message groups themselves, multiple orderings are valid now
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, VisibilityTimeout=0
        )
        ordering = [message["Body"] for message in response["Messages"]]
        assert ordering == ["g3-m1", "g1-m1", "g1-m2", "g2-m1", "g2-m2"]

    @markers.aws.validated
    def test_fifo_message_group_visibility_after_terminate_visibility_timeout(
        self, sqs_create_queue, aws_client
    ):
        """
        This test demonstrates that

        1. terminating the visibility timeout of a message in a group does not affect the visibility of
           other messages in the group
        2. a message group becomes visible as soon as a message within it has become visible again
        """
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {
            "FifoQueue": "true",
            "VisibilityTimeout": "30",
            "ContentBasedDeduplication": "true",
        }
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
        assert len(response["Messages"]) == 2
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"

        # both messages from group 1 have a visibility timeout of 30
        # we now terminate the visibility timeout of message 1
        aws_client.sqs.change_message_visibility(
            QueueUrl=queue_url,
            ReceiptHandle=response["Messages"][0]["ReceiptHandle"],
            VisibilityTimeout=0,
        )

        # when we now try to receive 3 messages, we get messages from both groups, but only the visible ones
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=3, WaitTimeSeconds=2
        )
        assert response["Messages"][0]["Body"] == "g2-m1"
        assert response["Messages"][1]["Body"] == "g1-m1"
        assert len(response["Messages"]) == 2

    @markers.aws.validated
    def test_fifo_message_group_visibility_after_change_message_visibility(
        self, sqs_create_queue, aws_client
    ):
        """
        This test demonstrates that

        1. changing the visibility timeout of a message in a group does not affect the visibility of
           other messages in the group
        2. a message group becomes visible as soon as a message within it has become visible again
        """
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {
            "FifoQueue": "true",
            "VisibilityTimeout": "30",
            "ContentBasedDeduplication": "true",
        }
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
        assert len(response["Messages"]) == 2
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"

        # both messages from group 1 have a visibility timeout of 30
        # we now change the visibility timeout of message 1 to 1
        aws_client.sqs.change_message_visibility(
            QueueUrl=queue_url,
            ReceiptHandle=response["Messages"][0]["ReceiptHandle"],
            VisibilityTimeout=1,
        )

        # let the updated visibility timeout expire
        time.sleep(2)

        # when we now try to receive 3 messages, we get messages from both groups, but only the visible ones
        # g1-m2 still has a visibility timeout of 30
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=3,
        )
        assert response["Messages"][0]["Body"] == "g2-m1"
        assert response["Messages"][1]["Body"] == "g1-m1"
        assert len(response["Messages"]) == 2

    @markers.aws.validated
    def test_fifo_message_group_visibility_after_delete(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        # we interleave a message from group 2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )
        # continue with group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        # we interleave another a message from group 2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m2", MessageGroupId="group-2"
        )
        # continue with group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m3", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m4", MessageGroupId="group-1"
        )
        # add group 3
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g3-m1", MessageGroupId="group-3"
        )

        # we receive two messages from group 1
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"

        # we delete all in-flight messages we received from group 1, which will make that group visible again
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][1]["ReceiptHandle"]
        )

        # draining the queue should include the message from group 1 we didn't delete earlier
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
        )
        ordering = [message["Body"] for message in response["Messages"]]

        # both are in principle valid orderings. it's not clear how this ordering in AWS happens
        assert ordering in (
            ["g2-m1", "g2-m2", "g1-m3", "g1-m4", "g3-m1"],  # aws
            ["g2-m1", "g2-m2", "g3-m1", "g1-m3", "g1-m4"],  # localstack
        )

    @markers.aws.validated
    def test_fifo_message_group_visibility_after_partial_delete(self, sqs_create_queue, aws_client):
        # this is almost the same test case as the one above, only that it doesn't fully delete the messages
        # it received so the message group remains in-flight.
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="group-1"
        )
        # we interleave a message from group 2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="group-2"
        )
        # continue with group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        # we interleave another a message from group 2
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g2-m2", MessageGroupId="group-2"
        )
        # continue with group 1
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m3", MessageGroupId="group-1"
        )
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g1-m4", MessageGroupId="group-1"
        )
        # add group 3
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="g3-m1", MessageGroupId="group-3"
        )

        # we receive two messages from group 1 (note that group 2 is not in there)
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=2)
        assert response["Messages"][0]["Body"] == "g1-m1"
        assert response["Messages"][1]["Body"] == "g1-m2"

        # we delete only one in-flight messages we received from group 1
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )

        # draining the queue should now not the message from group 1, since it's not yet visible
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
        )
        ordering = [message["Body"] for message in response["Messages"]]
        assert ordering == ["g2-m1", "g2-m2", "g3-m1"]

    @markers.aws.validated
    def test_fifo_queue_send_message_with_delay_seconds_fails(
        self, sqs_create_queue, snapshot, aws_client
    ):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )

        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url, MessageBody="message-1", MessageGroupId="1", DelaySeconds=2
            )

        snapshot.match("send_message", e.value)

    @markers.aws.validated
    def test_fifo_queue_send_message_with_delay_on_queue_works(self, sqs_create_queue, aws_client):
        delay_seconds = 2
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
                "DelaySeconds": str(delay_seconds),
            },
        )

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-3", MessageGroupId="1")

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
        assert response.get("Messages", []) == []

        time.sleep(delay_seconds + 1)

        response = aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=3)
        messages = response["Messages"]
        assert len(messages) == 3

        assert messages[0]["Body"] == "message-1"
        assert messages[1]["Body"] == "message-2"
        assert messages[2]["Body"] == "message-3"

    @markers.aws.validated
    def test_fifo_message_attributes(self, sqs_create_queue, snapshot, aws_client):
        snapshot.add_transformer(snapshot.transform.sqs_api())

        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
                "VisibilityTimeout": "0",
                "DeduplicationScope": "messageGroup",
                "FifoThroughputLimit": "perMessageGroupId",
            },
        )

        response = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="message-body-1",
            MessageGroupId="group-1",
            MessageDeduplicationId="dedup-1",
        )
        snapshot.match("send_message", response)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, AttributeNames=["All"], WaitTimeSeconds=10
        )
        snapshot.match("receive_message_0", response)
        # makes sure that attributes are mutated correctly
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, AttributeNames=["All"], WaitTimeSeconds=10
        )
        snapshot.match("receive_message_1", response)

    @markers.aws.validated
    def test_fifo_approx_number_of_messages(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        assert get_qsize(aws_client.sqs, queue_url) == 0

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g1-m2", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g1-m3", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g2-m1", MessageGroupId="2")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g3-m1", MessageGroupId="3")

        assert get_qsize(aws_client.sqs, queue_url) == 5

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=4, WaitTimeSeconds=1
        )

        if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
            time.sleep(5)

        assert get_qsize(aws_client.sqs, queue_url) == 1

        for message in response["Messages"]:
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
            )

        if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
            time.sleep(5)

        assert get_qsize(aws_client.sqs, queue_url) == 1

    @markers.aws.validated
    @pytest.mark.xfail(reason="not implemented in localstack at the moment")
    def test_fifo_delete_message_with_expired_receipt_handle(
        self, sqs_create_queue, aws_client, snapshot
    ):
        timeout = 1
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "VisibilityTimeout": f"{timeout}",
                "ContentBasedDeduplication": "true",
            },
        )
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="g1-m1", MessageGroupId="1")
        response = aws_client.sqs.receive_message(QueueUrl=queue_url)
        receipt_handle = response["Messages"][0]["ReceiptHandle"]

        snapshot.match("response", response)

        # let the timeout expire
        time.sleep(timeout + 1)
        # try to remove the message with the old receipt handle
        with pytest.raises(ClientError) as e:
            aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        snapshot.match("error", e.value.response)

    @markers.aws.validated
    def test_fifo_set_content_based_deduplication_strategy(
        self, sqs_create_queue, aws_client, snapshot
    ):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "SqsManagedSseEnabled": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        snapshot.match(
            "before-update",
            aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
        )

        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"ContentBasedDeduplication": "false"}
        )

        snapshot.match(
            "after-update",
            aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"]),
        )

    @markers.aws.validated
    def test_list_queue_tags(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        tags = {"testTag1": "test1", "testTag2": "test2"}

        aws_client.sqs.tag_queue(QueueUrl=queue_url, Tags=tags)
        tag_list = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)
        assert tags == tag_list["Tags"]

    @markers.aws.validated
    def test_queue_list_nonexistent_tags(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        tag_list = aws_client.sqs.list_queue_tags(QueueUrl=queue_url)

        assert "Tags" not in tag_list["ResponseMetadata"].keys()

    @markers.aws.validated
    def test_publish_get_delete_message(self, sqs_create_queue, aws_client):
        # visibility part handled by test_receive_terminate_visibility_timeout
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_body = "test message"
        result_send = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)

        result_recv = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == result_send["MessageId"]

        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_recv["Messages"][0]["ReceiptHandle"]
        )
        result_recv = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result_recv.keys()

    @markers.aws.validated
    def test_delete_message_deletes_with_change_visibility_timeout(
        self, sqs_create_queue, aws_client
    ):
        # Old name: test_delete_message_deletes_visibility_agnostic
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        message_id = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")[
            "MessageId"
        ]
        result_recv = aws_client.sqs.receive_message(QueueUrl=queue_url)
        result_follow_up = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id
        assert "Messages" not in result_follow_up.keys()

        receipt_handle = result_recv["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.change_message_visibility(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle, VisibilityTimeout=0
        )

        # check if the new timeout enables instant re-receiving, to ensure the message was deleted
        result_recv = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id

        receipt_handle = result_recv["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        result_follow_up = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result_follow_up.keys()

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_too_many_entries_in_batch_request(self, sqs_create_queue, snapshot, aws_client):
        message_count = 20
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_batch = [
            {
                "Id": f"message-{i}",
                "MessageBody": f"messageBody-{i}",
            }
            for i in range(message_count)
        ]

        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=message_batch)
        snapshot.match("test_too_many_entries_in_batch_request", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_invalid_batch_id(self, sqs_create_queue, snapshot, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_batch = [
            {
                "Id": f"message:{(batch_id := short_uid())}",
                "MessageBody": f"messageBody-{batch_id}",
            }
        ]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=message_batch)
        snapshot.match("test_invalid_batch_id", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_batch_missing_deduplication_id_for_fifo_queue(
        self, sqs_create_queue, snapshot, aws_client
    ):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "false",
            },
        )
        message_batch = [
            {
                "Id": f"message-{short_uid()}",
                "MessageBody": "messageBody",
                "MessageGroupId": "test-group",
                "MessageDeduplicationId": f"dedup-{short_uid()}",
            },
            {
                "Id": f"message-{short_uid()}",
                "MessageBody": "messageBody",
                "MessageGroupId": "test-group",
            },
        ]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=message_batch)
        snapshot.match("test_missing_deduplication_id_for_fifo_queue", e.value.response)

    @markers.parity.aws_validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_send_batch_missing_message_group_id_for_fifo_queue(
        self, sqs_create_queue, snapshot, aws_client
    ):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "false",
            },
        )
        message_batch = [
            {
                "Id": f"message-{short_uid()}",
                "MessageBody": "messageBody",
                "MessageGroupId": "test-group",
                "MessageDeduplicationId": f"dedup-{short_uid()}",
            },
            {
                "Id": f"message-{short_uid()}",
                "MessageBody": "messageBody",
                "MessageDeduplicationId": f"dedup-{short_uid()}",
            },
        ]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message_batch(QueueUrl=queue_url, Entries=message_batch)
        snapshot.match("test_missing_message_group_id_for_fifo_queue", e.value.response)

    @markers.aws.validated
    def test_publish_get_delete_message_batch(self, sqs_create_queue, aws_client):
        message_count = 10
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        message_batch = [
            {
                "Id": f"message-{i}",
                "MessageBody": f"messageBody-{i}",
            }
            for i in range(message_count)
        ]

        result_send_batch = aws_client.sqs.send_message_batch(
            QueueUrl=queue_url, Entries=message_batch
        )
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_recv = []
        i = 0
        while len(result_recv) < message_count and i < message_count:
            result_recv.extend(
                aws_client.sqs.receive_message(
                    QueueUrl=queue_url, MaxNumberOfMessages=message_count
                )["Messages"]
            )
            i += 1
        assert len(result_recv) == message_count

        ids_sent = set()
        ids_received = set()
        for i in range(message_count):
            ids_sent.add(successful[i]["MessageId"])
            ids_received.add((result_recv[i]["MessageId"]))

        assert ids_sent == ids_received

        delete_entries = [
            {"Id": message["MessageId"], "ReceiptHandle": message["ReceiptHandle"]}
            for message in result_recv
        ]
        aws_client.sqs.delete_message_batch(QueueUrl=queue_url, Entries=delete_entries)
        confirmation = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=message_count
        )
        assert "Messages" not in confirmation.keys()

    @markers.aws.validated
    @pytest.mark.parametrize(
        argnames="invalid_message_id", argvalues=["", "testLongId" * 10, "invalid:id"]
    )
    def test_delete_message_batch_invalid_msg_id(
        self, invalid_message_id, sqs_create_queue, snapshot, aws_client
    ):
        self._add_error_detail_transformer(snapshot)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        delete_entries = [{"Id": invalid_message_id, "ReceiptHandle": "testHandle1"}]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.delete_message_batch(QueueUrl=queue_url, Entries=delete_entries)
        snapshot.match("error_response", e.value.response)

    @markers.aws.validated
    def test_delete_message_batch_with_too_large_batch(
        self, sqs_create_queue, snapshot, aws_client
    ):
        self._add_error_detail_transformer(snapshot)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        message_batch = [
            {
                "Id": f"message-{i}",
                "MessageBody": f"messageBody-{i}",
            }
            for i in range(MAX_NUMBER_OF_MESSAGES)
        ]

        result_send_batch = aws_client.sqs.send_message_batch(
            QueueUrl=queue_url, Entries=message_batch
        )
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_send_batch = aws_client.sqs.send_message_batch(
            QueueUrl=queue_url, Entries=message_batch
        )
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_recv = []
        target_size = 2 * MAX_NUMBER_OF_MESSAGES

        def _receive_all_messages():
            result_recv.extend(
                aws_client.sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=min(MAX_NUMBER_OF_MESSAGES, target_size - len(result_recv)),
                )["Messages"]
            )
            assert len(result_recv) == target_size

        retry(_receive_all_messages, retries=7, sleep=0.5)

        delete_entries = [
            {"Id": str(i), "ReceiptHandle": msg["ReceiptHandle"]}
            for i, msg in enumerate(result_recv)
        ]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.delete_message_batch(QueueUrl=queue_url, Entries=delete_entries)
        snapshot.match("error_response", e.value.response)

    @markers.aws.validated
    def test_change_message_visibility_batch_with_too_large_batch(
        self, sqs_create_queue, snapshot, aws_client
    ):
        self._add_error_detail_transformer(snapshot)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        message_batch = [
            {
                "Id": f"message-{i}",
                "MessageBody": f"messageBody-{i}",
            }
            for i in range(MAX_NUMBER_OF_MESSAGES)
        ]

        result_send_batch = aws_client.sqs.send_message_batch(
            QueueUrl=queue_url, Entries=message_batch
        )
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_send_batch = aws_client.sqs.send_message_batch(
            QueueUrl=queue_url, Entries=message_batch
        )
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_recv = []
        target_size = 2 * MAX_NUMBER_OF_MESSAGES

        def _receive_all_messages():
            result_recv.extend(
                aws_client.sqs.receive_message(
                    QueueUrl=queue_url,
                    MaxNumberOfMessages=min(MAX_NUMBER_OF_MESSAGES, target_size - len(result_recv)),
                )["Messages"]
            )
            assert len(result_recv) == target_size

        retry(_receive_all_messages, retries=7, sleep=0.5)

        change_visibility_entries = [
            {"Id": str(i), "ReceiptHandle": msg["ReceiptHandle"], "VisibilityTimeout": 123}
            for i, msg in enumerate(result_recv)
        ]
        with pytest.raises(ClientError) as e:
            aws_client.sqs.change_message_visibility_batch(
                QueueUrl=queue_url, Entries=change_visibility_entries
            )
        snapshot.match("error_response", e.value.response)

    @markers.aws.validated
    def test_create_and_send_to_fifo_queue(self, sqs_create_queue, aws_client):
        # Old name: test_create_fifo_queue
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {"FifoQueue": "true"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        # it should preserve .fifo in the queue name
        assert queue_name in queue_url

        message_id = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="test",
            MessageDeduplicationId=f"dedup-{short_uid()}",
            MessageGroupId="test_group",
        )["MessageId"]

        result_recv = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id

    @markers.aws.validated
    def test_fifo_queue_requires_suffix(self, sqs_create_queue):
        queue_name = f"invalid-{short_uid()}"
        attributes = {"FifoQueue": "true"}

        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        e.match("InvalidParameterValue")

    @markers.aws.validated
    def test_standard_queue_cannot_have_fifo_suffix(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}.fifo"
        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name)
        e.match("InvalidParameterValue")

    @pytest.mark.xfail
    @markers.aws.validated
    def test_redrive_policy_attribute_validity(
        self, sqs_create_queue, sqs_get_queue_arn, aws_client
    ):
        dl_queue_name = f"dl-queue-{short_uid()}"
        dl_queue_url = sqs_create_queue(QueueName=dl_queue_name)
        dl_target_arn = sqs_get_queue_arn(dl_queue_url)
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        valid_max_receive_count = "42"
        invalid_max_receive_count = "invalid"

        with pytest.raises(Exception) as e:
            aws_client.sqs.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dl_target_arn})},
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            aws_client.sqs.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={
                    "RedrivePolicy": json.dumps({"maxReceiveCount": valid_max_receive_count})
                },
            )
        e.match("InvalidParameterValue")

        _invalid_redrive_policy = {
            "deadLetterTargetArn": dl_target_arn,
            "maxReceiveCount": invalid_max_receive_count,
        }

        with pytest.raises(Exception) as e:
            aws_client.sqs.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={"RedrivePolicy": json.dumps(_invalid_redrive_policy)},
            )
        e.match("InvalidParameterValue")

        _valid_redrive_policy = {
            "deadLetterTargetArn": dl_target_arn,
            "maxReceiveCount": valid_max_receive_count,
        }

        aws_client.sqs.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"RedrivePolicy": json.dumps(_valid_redrive_policy)}
        )

    @markers.aws.validated
    @pytest.mark.xfail(reason="behavior not implemented yet")
    def test_invalid_dead_letter_arn_rejected_before_lookup(self, sqs_create_queue, snapshot):
        dl_dummy_arn = "dummy"
        max_receive_count = 42
        _redrive_policy = {
            "deadLetterTargetArn": dl_dummy_arn,
            "maxReceiveCount": max_receive_count,
        }
        with pytest.raises(ClientError) as e:
            sqs_create_queue(Attributes={"RedrivePolicy": json.dumps(_redrive_policy)})

        snapshot.match("error_response", e.value.response)

    @markers.aws.validated
    def test_set_queue_policy(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"Policy": TEST_POLICY}
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        # accessing the policy generally and specifically
        attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )["Attributes"]
        policy = json.loads(attributes["Policy"])
        assert "sqs:SendMessage" == policy["Statement"][0]["Action"]
        attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["Policy"]
        )["Attributes"]
        policy = json.loads(attributes["Policy"])
        assert "sqs:SendMessage" == policy["Statement"][0]["Action"]

    @markers.aws.validated
    def test_set_empty_queue_policy(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"Policy": ""}
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )["Attributes"]
        assert "Policy" not in attributes.keys()

        # check if this behaviour holds on existing Policies as well
        attributes = {"Policy": TEST_POLICY}
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )["Attributes"]
        assert "sqs:SendMessage" in attributes["Policy"]

        attributes = {"Policy": ""}
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )["Attributes"]
        assert "Policy" not in attributes.keys()

    @markers.aws.validated
    def test_send_message_with_attributes(self, sqs_create_queue, aws_client):
        # Old name: test_send_message_attributes
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {
            "attr1": {"StringValue": "test1", "DataType": "String"},
            "attr2": {"StringValue": "test2", "DataType": "String"},
        }
        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=attributes
        )

        result_receive = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        messages = result_receive["Messages"]

        assert messages[0]["MessageId"] == result_send["MessageId"]
        assert messages[0]["MessageAttributes"] == attributes
        assert messages[0]["MD5OfMessageAttributes"] == result_send["MD5OfMessageAttributes"]

    @markers.aws.validated
    def test_send_message_with_binary_attributes(self, sqs_create_queue, snapshot, aws_client):
        # Old name: test_send_message_attributes
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {
            "attr1": {
                "BinaryValue": b"traceparent\x1e00-774062d6c37081a5a0b9b5b88e30627c-2d2482211f6489da-01",
                "DataType": "Binary",
            },
        }
        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=attributes
        )

        result_receive = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        messages = result_receive["Messages"]
        snapshot.match("binary-attrs-msg", result_receive)

        assert messages[0]["MessageId"] == result_send["MessageId"]
        assert messages[0]["MessageAttributes"] == attributes
        assert messages[0]["MD5OfMessageAttributes"] == result_send["MD5OfMessageAttributes"]

    @markers.aws.validated
    def test_sent_message_retains_attributes_after_receive(self, sqs_create_queue, aws_client):
        # Old name: test_send_message_retains_attributes
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"attr1": {"StringValue": "test1", "DataType": "String"}}
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=attributes
        )

        # receive should not interfere with message attributes
        aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, MessageAttributeNames=["All"]
        )
        receive_result = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        assert receive_result["Messages"][0]["MessageAttributes"] == attributes

    @markers.aws.validated
    def test_send_message_with_empty_string_attribute(self, sqs_queue, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.sqs.send_message(
                QueueUrl=sqs_queue,
                MessageBody="test",
                MessageAttributes={"ErrorDetails": {"StringValue": "", "DataType": "String"}},
            )

        assert e.value.response["Error"] == {
            "Type": "Sender",
            "Code": "InvalidParameterValue",
            "Message": "Message (user) attribute 'ErrorDetails' must contain a non-empty value of type 'String'.",
        }

    @markers.aws.validated
    def test_send_message_with_invalid_string_attributes(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        # base line against to detect general failure
        valid_attribute = {"attr.1øßä": {"StringValue": "Valida", "DataType": "String"}}
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=valid_attribute
        )

        def send_invalid(attribute):
            with pytest.raises(Exception) as e:
                aws_client.sqs.send_message(
                    QueueUrl=queue_url, MessageBody="test", MessageAttributes=attribute
                )
            e.match("Invalid")

        # String Attributes must not contain non-printable characters
        # See: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
        invalid_attribute = {
            "attr1": {"StringValue": f"Invalid-{chr(8)},{chr(11)}", "DataType": "String"}
        }
        send_invalid(invalid_attribute)

        invalid_name_prefixes = ["aWs.", "AMAZON.", "."]
        for prefix in invalid_name_prefixes:
            invalid_attribute = {
                f"{prefix}-Invalid-attr": {"StringValue": "Valid", "DataType": "String"}
            }
            send_invalid(invalid_attribute)

        # Some illegal characters
        invalid_name_characters = ["!", '"', "§", "(", "?"]
        for char in invalid_name_characters:
            invalid_attribute = {
                f"Invalid-{char}-attr": {"StringValue": "Valid", "DataType": "String"}
            }
            send_invalid(invalid_attribute)

        # limit is 256 chars
        too_long_name = "L" * 257
        invalid_attribute = {f"{too_long_name}": {"StringValue": "Valid", "DataType": "String"}}
        send_invalid(invalid_attribute)

        # FIXME: no double periods should be allowed
        # invalid_attribute = {
        #     "Invalid..Name": {"StringValue": "Valid", "DataType": "String"}
        # }
        # send_invalid(invalid_attribute)

        invalid_type = "Invalid"
        invalid_attribute = {
            "Attribute_name": {"StringValue": "Valid", "DataType": f"{invalid_type}"}
        }
        send_invalid(invalid_attribute)

        too_long_type = f"Number.{'L' * 256}"
        invalid_attribute = {
            "Attribute_name": {"StringValue": "Valid", "DataType": f"{too_long_type}"}
        }
        send_invalid(invalid_attribute)

        ends_with_dot = "Invalid."
        invalid_attribute = {f"{ends_with_dot}": {"StringValue": "Valid", "DataType": "String"}}
        send_invalid(invalid_attribute)

    @pytest.mark.xfail
    @markers.aws.unknown
    def test_send_message_with_invalid_fifo_parameters(self, sqs_create_queue, aws_client):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true"},
        )
        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody="test",
                MessageDeduplicationId=f"Invalid-{chr(8)}",
                MessageGroupId="1",
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody="test",
                MessageDeduplicationId="1",
                MessageGroupId=f"Invalid-{chr(8)}",
            )
        e.match("InvalidParameterValue")

    @markers.aws.validated
    def test_send_message_with_invalid_payload_characters(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        invalid_message_body = f"Invalid-{chr(0)}-{chr(8)}-{chr(19)}-{chr(65535)}"

        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=invalid_message_body)
        e.match("InvalidMessageContents")

    @markers.aws.validated
    def test_dead_letter_queue_config(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dead_letter_queue-{short_uid()}"

        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)
        url_parts = dl_queue_url.split("/")
        region = TEST_AWS_REGION_NAME
        dl_target_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )

        conf = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 50}
        attributes = {"RedrivePolicy": json.dumps(conf)}

        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        assert queue_url

    @markers.aws.validated
    def test_dead_letter_queue_list_sources(self, sqs_create_queue, aws_client):
        dl_queue_url = sqs_create_queue()
        url_parts = dl_queue_url.split("/")
        region = TEST_AWS_REGION_NAME
        dl_target_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )

        conf = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 50}
        attributes = {"RedrivePolicy": json.dumps(conf)}

        queue_url_1 = sqs_create_queue(Attributes=attributes)
        queue_url_2 = sqs_create_queue(Attributes=attributes)

        assert queue_url_1
        assert queue_url_2

        source_urls = aws_client.sqs.list_dead_letter_source_queues(QueueUrl=dl_queue_url)
        assert len(source_urls) == 2
        assert queue_url_1 in source_urls["queueUrls"]
        assert queue_url_2 in source_urls["queueUrls"]

    @markers.aws.validated
    def test_dead_letter_queue_with_fifo_and_content_based_deduplication(
        self, sqs_create_queue, sqs_get_queue_arn, aws_client
    ):
        dlq_url = sqs_create_queue(
            QueueName=f"test-dlq-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
                "MessageRetentionPeriod": "1209600",
            },
        )
        dlq_arn = sqs_get_queue_arn(dlq_url)

        queue_url = sqs_create_queue(
            QueueName=f"test-queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
                "VisibilityTimeout": "60",
                "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 2}),
            },
        )

        response = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="foobar", MessageGroupId="1"
        )
        message_id = response["MessageId"]

        # receive the messages twice, which is the maximum allowed
        aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1, VisibilityTimeout=0)
        aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1, VisibilityTimeout=0)
        # after this receive call the message should be in the DLQ
        aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1, VisibilityTimeout=0)

        # check the DLQ
        response = aws_client.sqs.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = response["Messages"][0]
        assert message["MessageId"] == message_id
        assert message["Body"] == "foobar"

    @markers.aws.validated
    def test_dead_letter_queue_max_receive_count(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dl-queue-{short_uid()}"
        dl_queue_url = sqs_create_queue(
            QueueName=dead_letter_queue_name, Attributes={"VisibilityTimeout": "0"}
        )

        # create arn
        url_parts = dl_queue_url.split("/")
        dl_target_arn = arns.sqs_queue_arn(url_parts[-1], account_id=url_parts[len(url_parts) - 2])

        policy = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 1}
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={"RedrivePolicy": json.dumps(policy), "VisibilityTimeout": "0"},
        )
        result_send = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")

        result_recv1_messages = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages")
        result_recv2_messages = aws_client.sqs.receive_message(QueueUrl=queue_url).get("Messages")
        # only one request received a message
        assert (result_recv1_messages is None) != (result_recv2_messages is None)

        assert poll_condition(
            lambda: "Messages" in aws_client.sqs.receive_message(QueueUrl=dl_queue_url), 5.0, 1.0
        )
        assert (
            aws_client.sqs.receive_message(QueueUrl=dl_queue_url)["Messages"][0]["MessageId"]
            == result_send["MessageId"]
        )

    @markers.aws.needs_fixing
    def test_dead_letter_queue_chain(self, sqs_create_queue, aws_client):
        # test a chain of 3 queues, with DLQ flow q1 -> q2 -> q3

        # create queues
        queue_names = [f"q-{short_uid()}", f"q-{short_uid()}", f"q-{short_uid()}"]
        queue_urls = []

        for queue_name in queue_names:
            url = sqs_create_queue(QueueName=queue_name, Attributes={"VisibilityTimeout": "0"})
            queue_urls.append(url)

        # set redrive policies
        for idx, queue_name in enumerate(queue_names[:2]):
            policy = {
                "deadLetterTargetArn": arns.sqs_queue_arn(
                    queue_names[idx + 1],
                    account_id=TEST_AWS_ACCOUNT_ID,
                    region_name=TEST_AWS_REGION_NAME,
                ),
                "maxReceiveCount": 1,
            }
            aws_client.sqs.set_queue_attributes(
                QueueUrl=queue_urls[idx],
                Attributes={"RedrivePolicy": json.dumps(policy), "VisibilityTimeout": "0"},
            )

        def _retry_receive(q_url):
            def _receive():
                _result = aws_client.sqs.receive_message(QueueUrl=q_url)
                assert _result.get("Messages")
                return _result

            return retry(_receive, sleep=1, retries=5)

        # send message
        result = aws_client.sqs.send_message(QueueUrl=queue_urls[0], MessageBody="test")
        # retrieve message from q1
        result = _retry_receive(queue_urls[0])
        assert len(result.get("Messages")) == 1
        # Wait for VisibilityTimeout to expire
        time.sleep(1.1)
        # retrieve message from q1 again -> no message, should go to DLQ q2
        result = aws_client.sqs.receive_message(QueueUrl=queue_urls[0])
        assert not result.get("Messages")
        # retrieve message from q2
        result = _retry_receive(queue_urls[1])
        assert len(result.get("Messages")) == 1
        # retrieve message from q2 again -> no message, should go to DLQ q3
        result = aws_client.sqs.receive_message(QueueUrl=queue_urls[1])
        assert not result.get("Messages")
        # retrieve message from q3
        result = _retry_receive(queue_urls[2])
        assert len(result.get("Messages")) == 1

    # TODO: check if test_set_queue_attribute_at_creation == test_create_queue_with_attributes

    @markers.aws.validated
    def test_get_specific_queue_attribute_response(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dead_letter_queue-{short_uid()}"

        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)
        region = TEST_AWS_REGION_NAME
        dl_result = aws_client.sqs.get_queue_attributes(
            QueueUrl=dl_queue_url, AttributeNames=["QueueArn"]
        )

        dl_queue_arn = dl_result["Attributes"]["QueueArn"]

        max_receive_count = 10
        _redrive_policy = {
            "deadLetterTargetArn": dl_queue_arn,
            "maxReceiveCount": max_receive_count,
        }
        message_retention_period = "604800"
        attributes = {
            "MessageRetentionPeriod": message_retention_period,
            "DelaySeconds": "10",
            "RedrivePolicy": json.dumps(_redrive_policy),
        }

        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        url_parts = queue_url.split("/")
        get_two_attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["MessageRetentionPeriod", "RedrivePolicy"],
        )
        get_single_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )
        # asserts
        constructed_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )
        redrive_policy = json.loads(get_two_attributes.get("Attributes").get("RedrivePolicy"))
        assert message_retention_period == get_two_attributes.get("Attributes").get(
            "MessageRetentionPeriod"
        )
        assert constructed_arn == get_single_attribute.get("Attributes").get("QueueArn")
        assert max_receive_count == redrive_policy.get("maxReceiveCount")

    @pytest.mark.xfail
    @markers.aws.validated
    def test_set_unsupported_attribute_fifo(self, sqs_create_queue, aws_client):
        # TODO: behaviour diverges from AWS
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        with pytest.raises(Exception) as e:
            aws_client.sqs.set_queue_attributes(
                QueueUrl=queue_url, Attributes={"FifoQueue": "true"}
            )
        e.match("InvalidAttributeName")

        fifo_queue_name = f"queue-{short_uid()}.fifo"
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )
        aws_client.sqs.set_queue_attributes(
            QueueUrl=fifo_queue_url, Attributes={"FifoQueue": "true"}
        )
        with pytest.raises(Exception) as e:
            aws_client.sqs.set_queue_attributes(
                QueueUrl=fifo_queue_url, Attributes={"FifoQueue": "false"}
            )
        e.match("InvalidAttributeValue")

    @markers.aws.validated
    def test_fifo_queue_send_multiple_messages_multiple_single_receives(
        self, sqs_create_queue, aws_client
    ):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true"},
        )
        message_count = 4
        group_id = f"fifo_group-{short_uid()}"
        sent_messages = []
        for i in range(message_count):
            result = aws_client.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=f"message{i}",
                MessageDeduplicationId=f"deduplication{i}",
                MessageGroupId=group_id,
            )
            sent_messages.append(result)

        for i in range(message_count):
            result = aws_client.sqs.receive_message(QueueUrl=queue_url)
            message = result["Messages"][0]
            assert message["Body"] == f"message{i}"
            assert message["MD5OfBody"] == sent_messages[i]["MD5OfMessageBody"]
            assert message["MessageId"] == sent_messages[i]["MessageId"]
            aws_client.sqs.delete_message(
                QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
            )

    @markers.aws.validated
    def test_fifo_content_based_message_deduplication_arrives_once(
        self, sqs_create_queue, aws_client
    ):
        # created for https://github.com/localstack/localstack/issues/6327
        queue_url = sqs_create_queue(
            QueueName=f"test-queue-{short_uid()}.fifo",
            Attributes={"FifoQueue": "true", "ContentBasedDeduplication": "true"},
        )
        item = '{"foo": "bar"}'
        group = "group-1"

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=item, MessageGroupId=group)
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=item, MessageGroupId=group)

        # first receive has the item
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        )
        assert len(response["Messages"]) == 1
        assert response["Messages"][0]["Body"] == item

        # second doesn't since the message has the same content
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        )
        assert response.get("Messages", []) == []

    @markers.aws.validated
    @pytest.mark.parametrize("content_based_deduplication", [True, False])
    def test_fifo_deduplication_arrives_once_after_delete(
        self,
        sqs_create_queue,
        aws_client,
        content_based_deduplication,
        snapshot,
    ):
        attributes = {"FifoQueue": "true"}
        if content_based_deduplication:
            attributes["ContentBasedDeduplication"] = "true"
        queue_url = sqs_create_queue(
            QueueName=f"test-queue-{short_uid()}.fifo",
            Attributes=attributes,
        )
        item = '{"foo": "bar"}'
        group = "group-1"
        kwargs = {}
        if not content_based_deduplication:
            kwargs["MessageDeduplicationId"] = "dedup1"
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=item, MessageGroupId=group, **kwargs
        )

        # first receive has the item
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=3)
        snapshot.match("get-messages", response)
        assert len(response["Messages"]) == 1
        assert response["Messages"][0]["Body"] == item
        # delete the item, we want to check that we don't receive a duplicate even after deletion
        # see https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )

        # republish the same message
        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=item, MessageGroupId=group, **kwargs
        )

        # second doesn't receive anything the deduplication id is the same
        response = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
        assert response.get("Messages", []) == []
        snapshot.match("get-messages-duplicate", response)

    @markers.aws.validated
    @pytest.mark.parametrize("content_based_deduplication", [True, False])
    def test_fifo_deduplication_not_on_message_group_id(
        self,
        sqs_create_queue,
        aws_client,
        content_based_deduplication,
        snapshot,
    ):
        attributes = {"FifoQueue": "true"}
        if content_based_deduplication:
            attributes["ContentBasedDeduplication"] = "true"
        queue_url = sqs_create_queue(
            QueueName=f"test-queue-{short_uid()}.fifo",
            Attributes=attributes,
        )
        item = '{"foo": "bar"}'
        kwargs = {}
        if not content_based_deduplication:
            kwargs["MessageDeduplicationId"] = "dedup1"

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=item, MessageGroupId="group-1", **kwargs
        )

        aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=item, MessageGroupId="group-2", **kwargs
        )

        # first receive has the item
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
        )
        assert len(response["Messages"]) == 1
        assert response["Messages"][0]["Body"] == item
        snapshot.match("get-messages", response)

        # second doesn't since the message has the same content
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=1
        )
        assert response.get("Messages", []) == []
        snapshot.match("get-dedup-messages", response)

    @markers.aws.validated
    @pytest.mark.xfail(
        reason="localstack allows queue names with slashes, but this should be deprecated"
    )
    def test_disallow_queue_name_with_slashes(self, sqs_create_queue):
        queue_name = f"queue/{short_uid()}/"
        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name)
        e.match("InvalidParameterValue")

    @markers.aws.validated
    def test_get_list_queues_with_query_auth(self, aws_http_client_factory):
        client = aws_http_client_factory("sqs", region="us-east-1")

        if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
            endpoint_url = "https://queue.amazonaws.com"
        else:
            endpoint_url = config.get_edge_url()

        response = client.get(
            endpoint_url, params={"Action": "ListQueues", "Version": "2012-11-05"}
        )

        assert response.status_code == 200
        assert b"<ListQueuesResponse" in response.content

    @markers.aws.validated
    def test_system_attributes_have_no_effect_on_attr_md5(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        msg_attrs_provider = {"timestamp": {"StringValue": "1493147359900", "DataType": "Number"}}
        aws_trace_header = {
            "AWSTraceHeader": {
                "StringValue": "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1",
                "DataType": "String",
            }
        }
        response_send = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=msg_attrs_provider
        )
        response_send_system_attr = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="test",
            MessageAttributes=msg_attrs_provider,
            MessageSystemAttributes=aws_trace_header,
        )
        assert (
            response_send["MD5OfMessageAttributes"]
            == response_send_system_attr["MD5OfMessageAttributes"]
        )
        assert response_send.get("MD5OfMessageSystemAttributes") is None
        assert (
            response_send_system_attr.get("MD5OfMessageSystemAttributes")
            == "5ae4d5d7636402d80f4eb6d213245a88"
        )

    @markers.aws.validated
    def test_inflight_message_requeue(self, sqs_create_queue, aws_client):
        visibility_timeout = 3
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(
            QueueName=queue_name
        )  # , Attributes={"VisibilityTimeout": str(visibility_timeout)})
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test1")
        result_receive1 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=visibility_timeout
        )
        time.sleep(visibility_timeout / 2)
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test2")
        time.sleep(visibility_timeout)
        result_receive2 = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=visibility_timeout
        )

        assert result_receive1["Messages"][0]["Body"] == result_receive2["Messages"][0]["Body"]

    @markers.aws.validated
    def test_sequence_number(self, sqs_create_queue, aws_client):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )
        message_content = f"test{short_uid()}"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"

        send_result_fifo = aws_client.sqs.send_message(
            QueueUrl=fifo_queue_url,
            MessageBody=message_content,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        assert "SequenceNumber" in send_result_fifo.keys()

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        send_result = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_content)
        assert "SequenceNumber" not in send_result

    @markers.aws.validated
    def test_fifo_sequence_number_increases(self, sqs_create_queue, aws_client):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )

        send_result_1 = aws_client.sqs.send_message(
            QueueUrl=fifo_queue_url,
            MessageBody="message-1",
            MessageGroupId="group",
            MessageDeduplicationId="m1",
        )
        send_result_2 = aws_client.sqs.send_message(
            QueueUrl=fifo_queue_url,
            MessageBody="message-2",
            MessageGroupId="group",
            MessageDeduplicationId="m2",
        )
        send_result_3 = aws_client.sqs.send_message(
            QueueUrl=fifo_queue_url,
            MessageBody="message-3",
            MessageGroupId="group",
            MessageDeduplicationId="m3",
        )

        assert int(send_result_1["SequenceNumber"]) < int(send_result_2["SequenceNumber"])
        assert int(send_result_2["SequenceNumber"]) < int(send_result_3["SequenceNumber"])

    @markers.aws.validated
    def test_posting_to_fifo_requires_deduplicationid_group_id(self, sqs_create_queue, aws_client):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"})
        message_content = f"test{short_uid()}"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"

        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url, MessageBody=message_content, MessageGroupId=group_id
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url, MessageBody=message_content, MessageDeduplicationId=dedup_id
            )
        e.match("MissingParameter")

    @markers.aws.validated
    def test_posting_to_queue_via_queue_name(self, sqs_create_queue, aws_client):
        # TODO: behaviour diverges from AWS
        queue_name = f"queue-{short_uid()}"
        sqs_create_queue(QueueName=queue_name)

        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_name, MessageBody="Using name instead of URL"
        )
        assert result_send["MD5OfMessageBody"] == "86a83f96652a1bfad3891e7d523750cb"
        assert result_send["ResponseMetadata"]["HTTPStatusCode"] == 200

    @markers.aws.validated
    def test_invalid_string_attributes_cause_invalid_parameter_value_error(
        self, sqs_create_queue, aws_client
    ):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        invalid_attribute = {
            "attr1": {"StringValue": f"Invalid-{chr(8)},{chr(11)}", "DataType": "String"}
        }

        with pytest.raises(Exception) as e:
            aws_client.sqs.send_message(
                QueueUrl=queue_url, MessageBody="test", MessageAttributes=invalid_attribute
            )
        e.match("InvalidParameterValue")

    @markers.aws.validated
    def test_change_message_visibility_not_permanent(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")
        result_receive = aws_client.sqs.receive_message(QueueUrl=queue_url)
        receipt_handle = result_receive.get("Messages")[0]["ReceiptHandle"]
        aws_client.sqs.change_message_visibility(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle, VisibilityTimeout=0
        )
        result_recv_1 = aws_client.sqs.receive_message(QueueUrl=queue_url)
        result_recv_2 = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert (
            result_recv_1.get("Messages")[0]["MessageId"]
            == result_receive.get("Messages")[0]["MessageId"]
        )
        assert "Messages" not in result_recv_2.keys()

    @pytest.mark.skip
    @markers.aws.unknown
    def test_dead_letter_queue_execution_lambda_mapping_preserves_id(
        self, sqs_create_queue, create_lambda_function, aws_client
    ):
        # TODO: lambda triggered dead letter delivery does not preserve the message id
        # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = "dl-queue-{}".format(short_uid())
        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)

        # create arn
        url_parts = dl_queue_url.split("/")
        region = TEST_AWS_REGION_NAME
        dl_target_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )

        policy = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 1}
        queue_url = sqs_create_queue(
            QueueName=queue_name, Attributes={"RedrivePolicy": json.dumps(policy)}
        )

        lambda_name = "lambda-{}".format(short_uid())
        create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_9,
        )
        # create arn
        url_parts = queue_url.split("/")
        queue_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )
        aws_client.lambda_.create_event_source_mapping(
            EventSourceArn=queue_arn, FunctionName=lambda_name
        )

        # add message to SQS, which will trigger the Lambda, resulting in an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_url, MessageBody=json.dumps(payload)
        )

        assert poll_condition(
            lambda: "Messages"
            in aws_client.sqs.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0),
            5.0,
            1.0,
        )
        result_recv = aws_client.sqs.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0)
        assert result_recv["Messages"][0]["MessageId"] == result_send["MessageId"]

    @markers.aws.validated
    def test_message_with_carriage_return(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_content = "{\r\n" + '"machineID" : "d357006e26ff47439e1ef894225d4307"' + "}"
        result_send = aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_content)
        result_receive = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert result_send["MD5OfMessageBody"] == result_receive["Messages"][0]["MD5OfBody"]
        assert message_content == result_receive["Messages"][0]["Body"]

    @markers.aws.validated
    def test_purge_queue(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        for i in range(3):
            message_content = f"test-0-{i}"
            aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_content)
        approx_nr_of_messages = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        assert int(approx_nr_of_messages["Attributes"]["ApproximateNumberOfMessages"]) > 1

        aws_client.sqs.purge_queue(QueueUrl=queue_url)

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url)
        assert "Messages" not in receive_result.keys()

        # test that adding messages after purge works
        for i in range(3):
            message_content = f"test-1-{i}"
            aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=message_content)

        messages = []

        def _collect():
            result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
            messages.extend(result.get("Messages", []))
            return len(messages) == 3

        assert poll_condition(_collect, timeout=10)
        assert {m["Body"] for m in messages} == {"test-1-0", "test-1-1", "test-1-2"}

    @markers.aws.validated
    def test_purge_queue_deletes_inflight_messages(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        for i in range(10):
            aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody=f"message-{i}")

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=3, WaitTimeSeconds=5, MaxNumberOfMessages=5
        )
        assert "Messages" in response

        aws_client.sqs.purge_queue(QueueUrl=queue_url)

        # wait for visibility timeout to expire
        time.sleep(3)

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
        assert "Messages" not in receive_result.keys()

    @markers.aws.validated
    def test_purge_queue_deletes_delayed_messages(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        for i in range(5):
            aws_client.sqs.send_message(
                QueueUrl=queue_url, MessageBody=f"message-{i}", DelaySeconds=2
            )

        aws_client.sqs.purge_queue(QueueUrl=queue_url)

        # wait for delay to expire
        time.sleep(2)

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)
        assert "Messages" not in receive_result.keys()

    @markers.aws.validated
    def test_purge_queue_clears_fifo_deduplication_cache(self, sqs_create_queue, aws_client):
        fifo_queue_name = f"test-queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"})
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"

        aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="message-1",
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )

        aws_client.sqs.purge_queue(QueueUrl=queue_url)

        aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="message-2",
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )

        receive_result = aws_client.sqs.receive_message(QueueUrl=queue_url, WaitTimeSeconds=1)

        assert len(receive_result["Messages"]) == 1
        message = receive_result["Messages"][0]

        assert message["Body"] == "message-2"

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_successive_purge_calls_fail(self, sqs_create_queue, monkeypatch, snapshot, aws_client):
        monkeypatch.setattr(config, "SQS_DELAY_PURGE_RETRY", True)
        queue_name = f"test-queue-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(queue_name, "<queue-name>"))

        queue_url = sqs_create_queue(QueueName=queue_name)

        aws_client.sqs.purge_queue(QueueUrl=queue_url)

        with pytest.raises(ClientError) as e:
            aws_client.sqs.purge_queue(QueueUrl=queue_url)

        snapshot.match("purge_queue_error", e.value.response)

    @markers.aws.validated
    def test_remove_message_with_old_receipt_handle(self, sqs_create_queue, aws_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="test")
        result_receive = aws_client.sqs.receive_message(QueueUrl=queue_url, VisibilityTimeout=1)
        time.sleep(2)
        receipt_handle = result_receive["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # This is more suited to the check than receiving because it simply
        # returns the number of elements in the queue, without further logic
        approx_nr_of_messages = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        assert int(approx_nr_of_messages["Attributes"]["ApproximateNumberOfMessages"]) == 0

    @markers.aws.only_localstack
    def test_list_queues_multi_region_without_endpoint_strategy(
        self, aws_client_factory, cleanups, monkeypatch
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "off")

        region1 = "us-east-1"
        region2 = "eu-central-1"
        region1_client = aws_client_factory(region_name=region1).sqs
        region2_client = aws_client_factory(region_name=region2).sqs

        queue1_name = f"queue-region1-{short_uid()}"
        queue2_name = f"queue-region2-{short_uid()}"

        queue1_url = region1_client.create_queue(QueueName=queue1_name)["QueueUrl"]
        cleanups.append(lambda: region1_client.delete_queue(QueueUrl=queue1_url))
        queue2_url = region2_client.create_queue(QueueName=queue2_name)["QueueUrl"]
        cleanups.append(lambda: region2_client.delete_queue(QueueUrl=queue2_url))

        # region should not be in the queue url with endpoint strategy "off"
        assert region1 not in queue1_url
        assert region1 not in queue2_url

        assert queue1_url in region1_client.list_queues().get("QueueUrls", [])
        assert queue2_url not in region1_client.list_queues().get("QueueUrls", [])

        assert queue1_url not in region2_client.list_queues().get("QueueUrls", [])
        assert queue2_url in region2_client.list_queues().get("QueueUrls", [])

    @markers.aws.validated
    def test_list_queues_multi_region_with_endpoint_strategy_domain(
        self, aws_client_factory, cleanups, monkeypatch
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "domain")

        region1 = "us-east-1"
        region2 = "eu-central-1"

        region1_client = aws_client_factory(region_name=region1).sqs
        region2_client = aws_client_factory(region_name=region2).sqs

        queue_name = f"queue-{short_uid()}"

        queue1_url = region1_client.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: region1_client.delete_queue(QueueUrl=queue1_url))
        queue2_url = region2_client.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: region2_client.delete_queue(QueueUrl=queue2_url))

        assert region1 not in queue1_url  # us-east-1 is not included in the default region
        assert region1 not in queue2_url
        assert f"{region2}.queue" in queue2_url  # all other regions are part of the endpoint-url

        assert queue1_url in region1_client.list_queues().get("QueueUrls", [])
        assert queue2_url not in region1_client.list_queues().get("QueueUrls", [])

        assert queue1_url not in region2_client.list_queues().get("QueueUrls", [])
        assert queue2_url in region2_client.list_queues().get("QueueUrls", [])

    @markers.aws.validated
    def test_get_queue_url_multi_region(self, aws_client_factory, cleanups, monkeypatch):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "domain")

        region1_client = aws_client_factory(region_name="us-east-1").sqs
        region2_client = aws_client_factory(region_name="eu-central-1").sqs

        queue_name = f"queue-{short_uid()}"

        queue1_url = region1_client.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: region1_client.delete_queue(QueueUrl=queue1_url))
        queue2_url = region2_client.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: region2_client.delete_queue(QueueUrl=queue2_url))

        assert queue1_url != queue2_url
        assert queue1_url == region1_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        assert queue2_url == region2_client.get_queue_url(QueueName=queue_name)["QueueUrl"]

    @pytest.mark.skip(
        reason="this is an AWS behaviour test that requires 5 minutes to run. Only execute manually"
    )
    @markers.aws.unknown
    def test_deduplication_interval(self, sqs_create_queue, aws_client):
        # TODO: AWS behaviour here "seems" inconsistent -> current code might need adaption
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"})
        message_content = f"test{short_uid()}"
        message_content_duplicate = f"{message_content}-duplicate"
        message_content_half_time = f"{message_content}-half_time"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"
        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        time.sleep(3)
        aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_duplicate,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        result_receive = aws_client.sqs.receive_message(QueueUrl=queue_url)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_receive["Messages"][0]["ReceiptHandle"]
        )
        result_receive_duplicate = aws_client.sqs.receive_message(QueueUrl=queue_url)

        assert result_send.get("MessageId") == result_receive.get("Messages")[0].get("MessageId")
        assert result_send.get("MD5OfMessageBody") == result_receive.get("Messages")[0].get(
            "MD5OfBody"
        )
        assert "Messages" not in result_receive_duplicate.keys()

        result_send = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        # ZZZZzzz...
        # Fifo Deduplication Interval is 5 minutes at minimum, + there seems no way to change it.
        # We give it a bit of leeway to avoid timing issues
        # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html
        time.sleep(2)
        aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_half_time,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        time.sleep(6 * 60)

        result_send_duplicate = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_duplicate,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        result_receive = aws_client.sqs.receive_message(QueueUrl=queue_url)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_receive["Messages"][0]["ReceiptHandle"]
        )
        result_receive_duplicate = aws_client.sqs.receive_message(QueueUrl=queue_url)

        assert result_send.get("MessageId") == result_receive.get("Messages")[0].get("MessageId")
        assert result_send.get("MD5OfMessageBody") == result_receive.get("Messages")[0].get(
            "MD5OfBody"
        )
        assert result_send_duplicate.get("MessageId") == result_receive_duplicate.get("Messages")[
            0
        ].get("MessageId")
        assert result_send_duplicate.get("MD5OfMessageBody") == result_receive_duplicate.get(
            "Messages"
        )[0].get("MD5OfBody")

    @markers.aws.validated
    def test_sse_queue_attributes(self, sqs_create_queue, snapshot, aws_client):
        # KMS server-side encryption (SSE)
        queue_url = sqs_create_queue()
        attributes = {
            "KmsMasterKeyId": "testKeyId",
            "KmsDataKeyReusePeriodSeconds": "6000",
            "SqsManagedSseEnabled": "false",
        }
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        response = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "KmsMasterKeyId",
                "KmsDataKeyReusePeriodSeconds",
                "SqsManagedSseEnabled",
            ],
        )
        snapshot.match("sse_kms_attributes", response)

        # SQS SSE
        queue_url = sqs_create_queue()
        attributes = {
            "SqsManagedSseEnabled": "true",
        }
        aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        response = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=[
                "KmsMasterKeyId",
                "KmsDataKeyReusePeriodSeconds",
                "SqsManagedSseEnabled",
            ],
        )
        snapshot.match("sse_sqs_attributes", response)

    @pytest.mark.xfail(reason="validation currently not implemented in localstack")
    @markers.aws.validated
    def test_sse_kms_and_sqs_are_mutually_exclusive(self, sqs_create_queue, snapshot, aws_client):
        queue_url = sqs_create_queue()
        attributes = {
            "KmsMasterKeyId": "testKeyId",
            "SqsManagedSseEnabled": "true",
        }

        with pytest.raises(ClientError) as e:
            aws_client.sqs.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        snapshot.match("error", e.value)

    @markers.aws.validated
    def test_receive_message_message_attribute_names_filters(
        self, sqs_create_queue, snapshot, aws_client
    ):
        """
        Receive message allows a list of filters to be passed with MessageAttributeNames. See:
        https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/sqs.html#SQS.Client.receive_message
        """
        queue_url = sqs_create_queue(Attributes={"VisibilityTimeout": "0"})

        response = aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="msg",
            MessageAttributes={
                "Help.Me": {"DataType": "String", "StringValue": "Me"},
                "Hello": {"DataType": "String", "StringValue": "There"},
                "General": {"DataType": "String", "StringValue": "Kenobi"},
            },
        )
        assert snapshot.match("send_message_response", response)

        def receive_message(message_attribute_names):
            return aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                WaitTimeSeconds=5,
                MessageAttributeNames=message_attribute_names,
            )

        # test empty filter
        response = receive_message([])
        # do the first check with the entire response
        assert snapshot.match("empty_filter", response)

        # test "All"
        response = receive_message(["All"])
        assert snapshot.match("all_name", response)

        # test "*"
        response = receive_message(["*"])
        assert snapshot.match("all_wildcard_asterisk", response["Messages"][0])

        # test ".*"
        response = receive_message([".*"])
        assert snapshot.match("all_wildcard", response["Messages"][0])

        # test only non-existent names
        response = receive_message(["Foo", "Help"])
        assert snapshot.match("only_non_existing_names", response["Messages"][0])

        # test all existing
        response = receive_message(["Hello", "General"])
        assert snapshot.match("only_existing", response["Messages"][0])

        # test existing and non-existing
        response = receive_message(["Foo", "Hello"])
        assert snapshot.match("existing_and_non_existing", response["Messages"][0])

        # test prefix filters
        response = receive_message(["Hel.*"])
        assert snapshot.match("prefix_filter", response["Messages"][0])

        # test illegal names
        response = receive_message(["AWS."])
        assert snapshot.match("illegal_name_1", response)
        response = receive_message(["..foo"])
        assert snapshot.match("illegal_name_2", response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Attributes.SenderId"])
    def test_receive_message_attribute_names_filters(self, sqs_create_queue, snapshot, aws_client):
        # TODO -> senderId in LS == account ID, but on AWS it looks quite different: [A-Z]{21}:<email>
        # account id is replaced with higher priority

        queue_url = sqs_create_queue(Attributes={"VisibilityTimeout": "0"})

        aws_client.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody="msg",
            MessageAttributes={
                "Foo": {"DataType": "String", "StringValue": "Bar"},
            },
        )

        def receive_message(attribute_names, message_attribute_names=None):
            return aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                WaitTimeSeconds=5,
                AttributeNames=attribute_names,
                MessageAttributeNames=message_attribute_names or [],
            )

        response = receive_message(["All"])
        assert snapshot.match("all_attributes", response)

        response = receive_message(["All"], ["All"])
        assert snapshot.match("all_system_and_message_attributes", response)

        response = receive_message(["SenderId"])
        assert snapshot.match("single_attribute", response)

        response = receive_message(["SenderId", "SequenceNumber"])
        assert snapshot.match("multiple_attributes", response)

    @markers.aws.validated
    def test_change_visibility_on_deleted_message_raises_invalid_parameter_value(
        self, sqs_queue, aws_client
    ):
        # prepare the fixture
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="foo")
        response = aws_client.sqs.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=5)
        handle = response["Messages"][0]["ReceiptHandle"]

        # check that it works as expected
        aws_client.sqs.change_message_visibility(
            QueueUrl=sqs_queue, ReceiptHandle=handle, VisibilityTimeout=42
        )

        # delete the message, the handle becomes invalid
        aws_client.sqs.delete_message(QueueUrl=sqs_queue, ReceiptHandle=handle)

        with pytest.raises(ClientError) as e:
            aws_client.sqs.change_message_visibility(
                QueueUrl=sqs_queue, ReceiptHandle=handle, VisibilityTimeout=42
            )

        err = e.value.response["Error"]
        assert err["Code"] == "InvalidParameterValue"
        assert (
            err["Message"]
            == f"Value {handle} for parameter ReceiptHandle is invalid. Reason: Message does not exist or is not "
            f"available for visibility timeout change."
        )

    @markers.aws.validated
    def test_delete_message_with_illegal_receipt_handle(self, sqs_queue, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.sqs.delete_message(QueueUrl=sqs_queue, ReceiptHandle="garbage")

        err = e.value.response["Error"]
        assert err["Code"] == "ReceiptHandleIsInvalid"
        assert err["Message"] == 'The input receipt handle "garbage" is not a valid receipt handle.'

    @markers.aws.validated
    def test_delete_message_with_deleted_receipt_handle(self, sqs_queue, aws_client):
        aws_client.sqs.send_message(QueueUrl=sqs_queue, MessageBody="foo")
        response = aws_client.sqs.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=5)
        handle = response["Messages"][0]["ReceiptHandle"]

        # does not raise errors even after successive calls
        aws_client.sqs.delete_message(QueueUrl=sqs_queue, ReceiptHandle=handle)
        aws_client.sqs.delete_message(QueueUrl=sqs_queue, ReceiptHandle=handle)
        aws_client.sqs.delete_message(QueueUrl=sqs_queue, ReceiptHandle=handle)

    # TODO: test message attributes and message system attributes

    def _add_error_detail_transformer(self, snapshot):
        """Adds a transformer to ignore {"Error": {"Detail": None, ...}} entries in snapshot error responses"""

        def _remove_error_details(snapshot_content: Dict, *args) -> Dict:
            for response in snapshot_content.values():
                response.get("Error", {}).pop("Detail", None)
            return snapshot_content

        snapshot.add_transformer(GenericTransformer(_remove_error_details))

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..Error.Detail"])
    def test_sqs_permission_lifecycle(self, sqs_queue, aws_client, snapshot, account_id):
        add_permission_response = aws_client.sqs.add_permission(
            QueueUrl=sqs_queue,
            AWSAccountIds=[account_id, "668614515564"],
            Actions=["ReceiveMessage"],
            Label="crossaccountpermission",
        )
        snapshot.match("add-permission-response", add_permission_response)

        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match("get-queue-policy-attribute", get_queue_policy_attribute)
        remove_permission_response = aws_client.sqs.remove_permission(
            QueueUrl=sqs_queue,
            Label="crossaccountpermission",
        )
        snapshot.match("remove-permission-response", remove_permission_response)
        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match("get-queue-policy-attribute-after-removal", get_queue_policy_attribute)

        # test two permissions with the same label
        aws_client.sqs.add_permission(
            QueueUrl=sqs_queue,
            AWSAccountIds=[account_id],
            Actions=["ReceiveMessage"],
            Label="crossaccountpermission",
        )
        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match(
            "get-queue-policy-attribute-first-account-same-label", get_queue_policy_attribute
        )

        with pytest.raises(ClientError) as e:
            aws_client.sqs.add_permission(
                QueueUrl=sqs_queue,
                AWSAccountIds=["668614515564"],
                Actions=["ReceiveMessage"],
                Label="crossaccountpermission",
            )
        snapshot.match("get-queue-policy-attribute-second-account-same-label", e.value.response)

        aws_client.sqs.add_permission(
            QueueUrl=sqs_queue,
            AWSAccountIds=[account_id],
            Actions=["ReceiveMessage"],
            Label="crossaccountpermission2",
        )
        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match(
            "get-queue-policy-attribute-second-account-different-label", get_queue_policy_attribute
        )

        aws_client.sqs.remove_permission(QueueUrl=sqs_queue, Label="crossaccountpermission")
        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match(
            "get-queue-policy-attribute-delete-first-permission", get_queue_policy_attribute
        )

        aws_client.sqs.remove_permission(QueueUrl=sqs_queue, Label="crossaccountpermission2")
        get_queue_policy_attribute = aws_client.sqs.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["Policy"]
        )
        snapshot.match(
            "get-queue-policy-attribute-delete-second-permission", get_queue_policy_attribute
        )
        with pytest.raises(ClientError) as e:
            aws_client.sqs.remove_permission(QueueUrl=sqs_queue, Label="crossaccountpermission2")
        snapshot.match("get-queue-policy-attribute-delete-non-existent-label", e.value.response)


@pytest.fixture()
def sqs_http_client(aws_http_client_factory):
    yield aws_http_client_factory("sqs", region=TEST_AWS_REGION_NAME)


class TestSqsQueryApi:
    @markers.aws.validated
    def test_get_queue_attributes_all(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "All",
            },
        )

        assert response.ok
        assert "<GetQueueAttributesResponse" in response.text
        assert "<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:" in response.text
        assert "<Attribute><Name>VisibilityTimeout</Name><Value>30" in response.text
        assert queue_url.split("/")[-1] in response.text

    @markers.aws.only_localstack
    def test_get_queue_attributes_works_without_authparams(self, sqs_create_queue):
        queue_url = sqs_create_queue()
        response = requests.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "All",
            },
        )

        assert response.ok
        assert "<GetQueueAttributesResponse" in response.text
        assert "<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:" in response.text
        assert "<Attribute><Name>VisibilityTimeout</Name><Value>30" in response.text
        assert queue_url.split("/")[-1] in response.text

    @markers.aws.validated
    def test_get_queue_attributes_with_query_args(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "QueueArn",
            },
        )

        assert response.ok
        assert "<GetQueueAttributesResponse" in response.text
        assert "<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:" in response.text
        assert "<Attribute><Name>VisibilityTimeout</Name>" not in response.text
        assert queue_url.split("/")[-1] in response.text

    @markers.aws.validated
    def test_invalid_action_raises_exception(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "FooBar",
                "Version": "2012-11-05",
            },
        )

        assert not response.ok
        assert "<Code>InvalidAction</Code>" in response.text
        assert "<Type>Sender</Type>" in response.text
        assert (
            "<Message>The action FooBar is not valid for this endpoint.</Message>" in response.text
        )

    @markers.aws.validated
    def test_valid_action_with_missing_parameter_raises_exception(
        self, sqs_create_queue, sqs_http_client
    ):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "SendMessage",
            },
        )

        assert not response.ok
        assert "<Code>MissingParameter</Code>" in response.text
        assert "<Type>Sender</Type>" in response.text
        assert (
            "<Message>The request must contain the parameter MessageBody.</Message>"
            in response.text
        )

    @markers.aws.validated
    def test_get_queue_attributes_of_fifo_queue(self, sqs_create_queue, sqs_http_client):
        queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes={"FifoQueue": "true"})

        assert ".fifo" in queue_url

        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "All",
            },
        )

        assert response.ok
        assert "<Name>FifoQueue</Name><Value>true</Value>" in response.text
        assert queue_name in response.text

    @markers.aws.validated
    def test_get_queue_attributes_with_invalid_arg_returns_error(
        self, sqs_create_queue, sqs_http_client
    ):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "Foobar",
            },
        )

        assert not response.ok
        assert "<Type>Sender</Type>" in response.text
        assert "<Code>InvalidAttributeName</Code>" in response.text
        assert "<Message>Unknown Attribute Foobar.</Message>" in response.text

    @markers.aws.validated
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_get_delete_queue(
        self, monkeypatch, sqs_create_queue, sqs_http_client, sqs_queue_exists, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "DeleteQueue",
            },
        )
        assert response.ok
        assert "<DeleteQueueResponse " in response.text

        assert poll_condition(lambda: not sqs_queue_exists(queue_url), timeout=5)

    @markers.aws.validated
    def test_get_send_and_receive_messages(self, sqs_create_queue, sqs_http_client):
        queue1_url = sqs_create_queue()
        queue2_url = sqs_create_queue()

        # items in queue 1
        response = sqs_http_client.get(
            queue1_url,
            params={
                "Action": "SendMessage",
                "MessageBody": "foobar",
            },
        )
        assert response.ok

        # no items in queue 2
        response = sqs_http_client.get(
            queue2_url,
            params={
                "Action": "ReceiveMessage",
            },
        )
        assert response.ok
        assert "foobar" not in response.text
        assert "<ReceiveMessageResult/>" in response.text.replace(
            " />", "/>"
        )  # expect response to be empty

        # get items from queue 1
        response = sqs_http_client.get(
            queue1_url,
            params={
                "Action": "ReceiveMessage",
            },
        )

        assert response.ok
        assert "<Body>foobar</Body>" in response.text
        assert "<MD5OfBody>" in response.text

    @markers.aws.validated
    def test_get_on_deleted_queue_fails(
        self, sqs_create_queue, sqs_http_client, sqs_queue_exists, aws_client
    ):
        queue_url = sqs_create_queue()

        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        assert poll_condition(lambda: not sqs_queue_exists(queue_url), timeout=5)

        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "QueueArn",
            },
        )

        assert "<Code>AWS.SimpleQueueService.NonExistentQueue</Code>" in response.text
        assert "<Message>The specified queue does not exist for this wsdl version" in response.text
        assert response.status_code == 400

    @markers.aws.validated
    def test_get_without_query_returns_unknown_operation(self, sqs_create_queue, sqs_http_client):
        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        assert queue_url.endswith(f"/{queue_name}")

        response = sqs_http_client.get(queue_url)
        assert "<UnknownOperationException" in response.text
        assert response.status_code == 404

    @markers.aws.validated
    def test_get_create_queue_fails(self, sqs_create_queue, sqs_http_client):
        queue1_url = sqs_create_queue()
        queue2_name = f"test-queue-{short_uid()}"

        response = sqs_http_client.get(
            queue1_url,
            params={
                "Action": "CreateQueue",
                "QueueName": queue2_name,
            },
        )

        assert "<Code>InvalidAction</Code>" in response.text
        assert "<Message>The action CreateQueue is not valid for this endpoint" in response.text
        assert response.status_code == 400

    @markers.aws.validated
    def test_get_list_queues_fails(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "ListQueues",
            },
        )
        assert "<Code>InvalidAction</Code>" in response.text
        assert "<Message>The action ListQueues is not valid for this endpoint" in response.text
        assert response.status_code == 400

    @markers.aws.validated
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_get_queue_url_works_for_same_queue(
        self,
        monkeypatch,
        sqs_create_queue,
        sqs_http_client,
        strategy,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue_url,
            params={
                "Action": "GetQueueUrl",
                "QueueName": queue_url.split("/")[-1],
            },
        )
        assert f"<QueueUrl>{queue_url}</QueueUrl>" in response.text
        assert response.status_code == 200

    @markers.aws.validated
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    def test_get_queue_url_work_for_different_queue(
        self, monkeypatch, sqs_create_queue, sqs_http_client, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        # for some reason this is allowed 🤷
        queue1_url = sqs_create_queue()
        queue2_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue1_url,
            params={
                "Action": "GetQueueUrl",
                "QueueName": queue2_url.split("/")[-1],
            },
        )
        assert f"<QueueUrl>{queue2_url}</QueueUrl>" in response.text
        assert queue1_url not in response.text
        assert response.status_code == 200

    @markers.aws.validated
    @pytest.mark.parametrize("strategy", ["domain", "path", "off"])
    def test_endpoint_strategy_with_multi_region(
        self,
        strategy,
        sqs_http_client,
        aws_client_factory,
        aws_http_client_factory,
        monkeypatch,
        cleanups,
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        queue_name = f"test-queue-{short_uid()}"
        region1 = "us-west-1"
        region2 = "eu-north-1"

        sqs_region1 = aws_client_factory(region_name=region1).sqs
        sqs_region2 = aws_client_factory(region_name=region2).sqs

        queue_region1 = sqs_region1.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: sqs_region1.delete_queue(QueueUrl=queue_region1))
        queue_region2 = sqs_region2.create_queue(QueueName=queue_name)["QueueUrl"]
        cleanups.append(lambda: sqs_region2.delete_queue(QueueUrl=queue_region2))

        if strategy == "off":
            assert queue_region1 == queue_region2
        else:
            assert queue_region1 != queue_region2
            assert region2 in queue_region2
            # us-east-1 is the default region, so it's not necessarily part of the queue URL

        client_region1 = aws_http_client_factory("sqs", region1)
        client_region2 = aws_http_client_factory("sqs", region2)

        response = client_region1.get(
            queue_region1, params={"Action": "SendMessage", "MessageBody": "foobar"}
        )
        assert response.ok

        # shouldn't return anything
        response = client_region2.get(
            queue_region2, params={"Action": "ReceiveMessage", "VisibilityTimeout": "0"}
        )
        assert response.ok
        assert "foobar" not in response.text

        # should return the message
        response = client_region1.get(
            queue_region1, params={"Action": "ReceiveMessage", "VisibilityTimeout": "0"}
        )
        assert response.ok
        assert "foobar" in response.text

    @markers.aws.only_localstack
    def test_queue_url_format_path_strategy(self, sqs_create_queue, monkeypatch):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", "path")
        queue_name = f"path_queue_{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        assert (
            f"localhost:4566/queue/{TEST_AWS_REGION_NAME}/{TEST_AWS_ACCOUNT_ID}/{queue_name}"
            in queue_url
        )

    @markers.aws.validated
    def test_overwrite_queue_url_in_params(self, sqs_create_queue, sqs_http_client):
        # here, queue1 url simply serves as AWS endpoint but we pass queue2 url in the request arg
        queue1_url = sqs_create_queue()
        queue2_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue1_url,
            params={
                "Action": "GetQueueAttributes",
                "QueueUrl": queue2_url,
                "AttributeName.1": "QueueArn",
            },
        )

        assert response.ok
        assert "<Attribute><Name>QueueArn</Name><Value>arn:aws:sqs:" in response.text
        assert queue1_url.split("/")[-1] not in response.text
        assert queue2_url.split("/")[-1] in response.text

    @pytest.mark.xfail(reason="json serialization not supported yet")
    @markers.aws.validated
    def test_get_list_queues_fails_json_format(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()

        response = sqs_http_client.get(
            queue_url,
            headers={"Accept": "application/json"},
            params={
                "Action": "ListQueues",
            },
        )
        assert response.status_code == 400

        doc = response.json()
        assert doc["Error"]["Code"] == "InvalidAction"
        assert doc["Error"]["Message"] == "The action ListQueues is not valid for this endpoint."

    @pytest.mark.xfail(reason="json serialization not supported yet")
    @markers.aws.validated
    def test_get_queue_attributes_json_format(self, sqs_create_queue, sqs_http_client):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(
            queue_url,
            headers={"Accept": "application/json"},
            params={
                "Action": "GetQueueAttributes",
                "AttributeName.1": "All",
            },
        )

        assert response.ok
        doc = response.json()
        assert "GetQueueAttributesResponse" in doc
        attributes = doc["GetQueueAttributesResponse"]["GetQueueAttributesResult"]["Attributes"]

        for attribute in attributes:
            if attribute["Name"] == "QueueArn":
                assert "arn:aws:sqs" in attribute["Value"]
                assert queue_url.split("/")[-1] in attribute["Value"]
                return

        pytest.fail(f"no QueueArn attribute in attributes {attributes}")

    @markers.aws.validated
    def test_get_without_query_json_format_returns_returns_xml(
        self, sqs_create_queue, sqs_http_client
    ):
        queue_url = sqs_create_queue()
        response = sqs_http_client.get(queue_url, headers={"Accept": "application/json"})
        assert "<UnknownOperationException" in response.text
        assert response.status_code == 404

    # TODO: write tests for making POST requests (not clear how signing would work without custom code)
    #  https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-making-api-requests.html#structure-post-request


class TestSQSMultiAccounts:
    @pytest.mark.parametrize("strategy", ["domain", "path"])
    @markers.aws.only_localstack
    def test_cross_account_access(
        self, monkeypatch, sqs_create_queue, secondary_aws_client, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)

        # Create a queue using primary test credentials
        queue_url = sqs_create_queue()

        # Create a client configured with secondary test credentials
        client = secondary_aws_client.sqs

        assert client.get_queue_attributes(QueueUrl=queue_url)
        assert client.send_message(QueueUrl=queue_url, MessageBody="foo")["MessageId"]
        response = client.receive_message(QueueUrl=queue_url)
        assert len(response["Messages"]) == 1
        assert client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )
        assert client.purge_queue(QueueUrl=queue_url)

        # On production AWS, cross-account access is not applicable for following operations,
        # but this is not enforced in LocalStack
        # - AddPermission
        # - CreateQueue
        # - DeleteQueue
        # - ListQueues
        # - ListQueueTags
        # - RemovePermission
        # - SetQueueAttributes
        # - TagQueue
        # - UntagQueue

    @pytest.mark.parametrize("strategy", ["domain", "path"])
    @markers.aws.only_localstack
    def test_cross_account_get_queue_url(
        self, monkeypatch, sqs_create_queue, secondary_aws_client, strategy
    ):
        monkeypatch.setattr(config, "SQS_ENDPOINT_STRATEGY", strategy)
        queue_name = f"test-queue-cross-account-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        account_id, region_name, queue_name_from_url = parse_queue_url(queue_url)
        assert account_id == DEFAULT_AWS_ACCOUNT_ID
        assert region_name == TEST_AWS_REGION_NAME
        assert queue_name_from_url == queue_name

        # Get another client in the same region
        client = secondary_aws_client.sqs

        # test that you can get the queue url from another account, if you set the owner
        queue_url_2 = client.get_queue_url(QueueName=queue_name, QueueOwnerAWSAccountId=account_id)[
            "QueueUrl"
        ]
        assert queue_url == queue_url_2

    @markers.aws.only_localstack
    def test_delete_queue_multi_account(
        self, aws_client, secondary_aws_client, aws_http_client_factory, cleanups
    ):
        # set up regular boto clients for creating the queues
        client1 = aws_client.sqs
        client2 = secondary_aws_client.sqs

        # set up the queues in the two accounts
        prefix = f"test-{short_uid()}-"
        queue1_name = f"{prefix}-queue-{short_uid()}"
        queue2_name = f"{prefix}-queue-{short_uid()}"
        response = client1.create_queue(QueueName=queue1_name)
        queue1_url = response["QueueUrl"]
        assert parse_queue_url(queue1_url)[0] == TEST_AWS_ACCOUNT_ID

        response = client2.create_queue(QueueName=queue2_name)
        queue2_url = response["QueueUrl"]
        assert parse_queue_url(queue2_url)[0] == SECONDARY_TEST_AWS_ACCOUNT_ID

        # now prepare the query api clients
        client1_http = aws_http_client_factory(
            service="sqs",
            region=TEST_AWS_REGION_NAME,
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )

        client2_http = aws_http_client_factory(
            service="sqs",
            region=TEST_AWS_REGION_NAME,  # Use the same region for both clients
            aws_access_key_id=SECONDARY_TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=SECONDARY_TEST_AWS_SECRET_ACCESS_KEY,
        )

        # try and delete the queue from one account using the query API and make sure a) it works, and b) it's not deleting the queue from the other account
        assert len(client1.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])) == 1
        assert len(client2.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])) == 1
        response = client1_http.post(queue1_url, params={"Action": "DeleteQueue"})
        assert response.ok
        assert len(client1.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])) == 0
        assert queue2_url in client2.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])

        # now delete the second one
        client2_http.post(queue2_url, params={"Action": "DeleteQueue"})
        assert response.ok
        assert len(client2.list_queues(QueueNamePrefix=prefix).get("QueueUrls", [])) == 0
