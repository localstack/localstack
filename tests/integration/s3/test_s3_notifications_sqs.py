import json
import logging
from typing import TYPE_CHECKING, Dict, List, Protocol

import pytest
import requests
from boto3.s3.transfer import KB, TransferConfig

from localstack.utils.aws import aws_stack
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition

if TYPE_CHECKING:
    from mypy_boto3_s3 import S3Client
    from mypy_boto3_s3.literals import EventType
    from mypy_boto3_sqs import SQSClient

LOG = logging.getLogger(__name__)


class NotificationFactory(Protocol):
    """
    A protocol for connecting a bucket to a queue with a notification configurations and the necessary policies.
    """

    def __call__(self, bucket_name: str, queue_url: str, events: List["EventType"]) -> None:
        """
        Creates a new notification configuration and respective policies.

        :param bucket_name: the source bucket
        :param queue_url: the target SQS queue
        :param events: the type of S3 events to trigger the notification
        :return: None
        """
        raise NotImplementedError


def get_queue_arn(sqs_client, queue_url: str) -> str:
    """
    Returns the given Queue's ARN. Expects the Queue to exist.

    :param sqs_client: the boto3 client
    :param queue_url: the queue URL
    :return: the QueueARN
    """
    response = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    return response["Attributes"]["QueueArn"]


def create_sqs_bucket_notification(
    s3_client: "S3Client",
    sqs_client: "SQSClient",
    bucket_name: str,
    queue_url: str,
    events: List["EventType"],
):
    """A NotificationFactory."""
    queue_arn = get_queue_arn(sqs_client, queue_url)
    assert queue_arn
    bucket_arn = aws_stack.s3_bucket_arn(bucket_name)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
            }
        ],
    }
    sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})

    s3_client.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration=dict(
            QueueConfigurations=[
                dict(
                    QueueArn=queue_arn,
                    Events=events,
                )
            ]
        ),
    )


@pytest.fixture
def s3_create_sqs_bucket_notification(s3_client, sqs_client) -> NotificationFactory:
    """
    A factory fixture for creating sqs bucket notifications.

    :param s3_client:
    :param sqs_client:
    :return:
    """

    def factory(bucket_name: str, queue_url: str, events: List["EventType"]):
        return create_sqs_bucket_notification(s3_client, sqs_client, bucket_name, queue_url, events)

    return factory


def sqs_collect_s3_events(
    sqs_client: "SQSClient", queue_url: str, min_events: int, timeout: int = 10
) -> List[Dict]:
    """
    Polls the given queue for the given amount of time and extracts and flattens from the received messages all
    events (messages that have a "Records" field in their body, and where the records can be json-deserialized).

    :param sqs_client: the boto3 client to use
    :param queue_url: the queue URL to listen from
    :param min_events: the minimum number of events to receive to wait for
    :param timeout: the number of seconds to wait before raising an assert error
    :return: a list with the deserialized records from the SQS messages
    """

    events = []

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

            assert "Records" in body, "Unexpected event received"

            doc = json.loads(body)
            events.extend(doc["Records"])

        return len(events)

    assert poll_condition(lambda: collect_events() >= min_events, timeout=timeout)

    return events


class TestS3NotificationsToSQS:
    @pytest.mark.aws_validated
    def test_object_created_put(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:Put"])

        s3_client.put_bucket_versioning(
            Bucket=bucket_name, VersioningConfiguration={"Status": "Enabled"}
        )

        obj0 = s3_client.put_object(Bucket=bucket_name, Key="my_key_0", Body="something")
        obj1 = s3_client.put_object(Bucket=bucket_name, Key="my_key_1", Body="something else")

        # collect s3 events from SQS queue
        events = sqs_collect_s3_events(sqs_client, queue_url, min_events=2)

        assert len(events) == 2, f"unexpected number of events in {events}"

        # assert
        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == "my_key_0"
        assert events[0]["s3"]["object"]["size"] == 9
        assert events[0]["s3"]["object"]["versionId"]
        assert obj0["VersionId"] == events[0]["s3"]["object"]["versionId"]

        assert events[1]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[1]["s3"]["bucket"]["name"] == bucket_name
        assert events[1]["s3"]["object"]["key"] == "my_key_1"
        assert events[1]["s3"]["object"]["size"] == 14
        assert events[1]["s3"]["object"]["versionId"]
        assert obj1["VersionId"] == events[1]["s3"]["object"]["versionId"]

    @pytest.mark.aws_validated
    def test_object_created_copy(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:Copy"])

        src_key = "src-dest-%s" % short_uid()
        dest_key = "key-dest-%s" % short_uid()

        s3_client.put_object(Bucket=bucket_name, Key=src_key, Body="something")

        assert not sqs_collect_s3_events(
            sqs_client, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        s3_client.copy_object(
            Bucket=bucket_name,
            CopySource={"Bucket": bucket_name, "Key": src_key},
            Key=dest_key,
        )

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectCreated:Copy"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    def test_object_created_and_object_removed(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(
            bucket_name, queue_url, ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        )

        src_key = "src-dest-%s" % short_uid()
        dest_key = "key-dest-%s" % short_uid()

        # event0 = PutObject
        s3_client.put_object(Bucket=bucket_name, Key=src_key, Body="something")
        # event1 = CopyObject
        s3_client.copy_object(
            Bucket=bucket_name,
            CopySource={"Bucket": bucket_name, "Key": src_key},
            Key=dest_key,
        )
        # event3 = DeleteObject
        s3_client.delete_object(Bucket=bucket_name, Key=src_key)

        # collect events
        events = sqs_collect_s3_events(sqs_client, queue_url, 3)
        assert len(events) == 3, f"unexpected number of events in {events}"

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == src_key

        assert events[1]["eventName"] == "ObjectCreated:Copy"
        assert events[1]["s3"]["bucket"]["name"] == bucket_name
        assert events[1]["s3"]["object"]["key"] == dest_key

        assert events[2]["eventName"] == "ObjectRemoved:Delete"
        assert events[2]["s3"]["bucket"]["name"] == bucket_name
        assert events[2]["s3"]["object"]["key"] == src_key

    @pytest.mark.aws_validated
    def test_object_created_complete_multipart_upload(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        tmpdir,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        key = "test-key"

        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])

        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html#multipart-transfers
        config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        file = tmpdir / "test-file.bin"
        data = b"1" * (6 * KB)  # create 6 kilobytes of ones
        file.write(data=data, mode="w")
        s3_client.upload_file(
            Bucket=bucket_name, Key=key, Filename=str(file.realpath()), Config=config
        )

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)

        assert events[0]["eventName"] == "ObjectCreated:CompleteMultipartUpload"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == key
        assert events[0]["s3"]["object"]["size"] == file.size()

    @pytest.mark.aws_validated
    def test_key_encoding(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # test for https://github.com/localstack/localstack/issues/2741

        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])

        key = "a@b"
        key_encoded = "a%40b"
        s3_client.put_object(Bucket=bucket_name, Key=key, Body="something")

        events = sqs_collect_s3_events(sqs_client, queue_url, min_events=1)

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key_encoded

    @pytest.mark.aws_validated
    def test_object_created_put_with_presigned_url_upload(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        key = "key-by-hostname"

        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])
        url = s3_client.generate_presigned_url(
            "put_object", Params={"Bucket": bucket_name, "Key": key}
        )
        requests.put(url, data="something", verify=False)

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)
        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key

    @pytest.mark.aws_validated
    def test_object_tagging_put_event(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectTagging:Put"])

        dest_key = "key-dest-%s" % short_uid()

        s3_client.put_object(Bucket=bucket_name, Key=dest_key, Body="FooBarBlitz")

        assert not sqs_collect_s3_events(
            sqs_client, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        s3_client.put_object_tagging(
            Bucket=bucket_name,
            Key=dest_key,
            Tagging={
                "TagSet": [
                    {"Key": "swallow_type", "Value": "african"},
                ]
            },
        )

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Put"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    def test_object_tagging_delete_event(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
    ):
        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectTagging:Delete"])

        dest_key = "key-dest-%s" % short_uid()

        s3_client.put_object(Bucket=bucket_name, Key=dest_key, Body="FooBarBlitz")

        assert not sqs_collect_s3_events(
            sqs_client, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        s3_client.put_object_tagging(
            Bucket=bucket_name,
            Key=dest_key,
            Tagging={
                "TagSet": [
                    {"Key": "swallow_type", "Value": "african"},
                ]
            },
        )

        s3_client.delete_object_tagging(
            Bucket=bucket_name,
            Key=dest_key,
        )

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Delete"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    def test_xray_header(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        cleanups,
    ):
        # test for https://github.com/localstack/localstack/issues/3686

        # add boto hook
        def add_xray_header(request, **kwargs):
            request.headers[
                "X-Amzn-Trace-Id"
            ] = "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"

        s3_client.meta.events.register("before-send.s3.*", add_xray_header)
        # make sure the hook gets cleaned up after the test
        cleanups.append(
            lambda: s3_client.meta.events.unregister("before-send.s3.*", add_xray_header)
        )

        key = "test-data"
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()

        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])

        # put an object where the bucket_name is in the path
        s3_client.put_object(Bucket=bucket_name, Key=key, Body="something")

        messages = []

        def get_messages():
            resp = sqs_client.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["AWSTraceHeader"],
                MessageAttributeNames=["All"],
                VisibilityTimeout=0,
            )
            for m in resp["Messages"]:
                if "s3:TestEvent" in m["Body"]:
                    continue
                messages.append(m)

            return len(messages)

        assert poll_condition(lambda: get_messages() >= 1, timeout=10)

        assert "AWSTraceHeader" in messages[0]["Attributes"]
        assert (
            messages[0]["Attributes"]["AWSTraceHeader"]
            == "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
        )
