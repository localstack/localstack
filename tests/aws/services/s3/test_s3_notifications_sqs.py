import json
import logging
from io import BytesIO
from typing import TYPE_CHECKING, Dict, List, Protocol

import pytest
import requests
from boto3.s3.transfer import KB, TransferConfig
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.s3.conftest import TEST_S3_IMAGE, is_v2_provider

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


def set_policy_for_queue(sqs_client, queue_url, bucket_name):
    queue_arn = get_queue_arn(sqs_client, queue_url)
    assert queue_arn
    bucket_arn = arns.s3_bucket_arn(bucket_name)

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
    return queue_arn


def create_sqs_bucket_notification(
    s3_client: "S3Client",
    sqs_client: "SQSClient",
    bucket_name: str,
    queue_url: str,
    events: List["EventType"],
):
    """A NotificationFactory."""
    queue_arn = set_policy_for_queue(sqs_client, queue_url, bucket_name)
    s3_client.put_bucket_notification_configuration(
        Bucket=bucket_name,
        NotificationConfiguration=dict(
            QueueConfigurations=[dict(QueueArn=queue_arn, Events=events)]
        ),
    )


@pytest.fixture
def s3_create_sqs_bucket_notification(aws_client) -> NotificationFactory:
    """
    A factory fixture for creating sqs bucket notifications.
    """

    def factory(
        bucket_name: str,
        queue_url: str,
        events: List["EventType"],
        s3_client=aws_client.s3,
        sqs_client=aws_client.sqs,
    ):
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

    def collect_events() -> None:
        _response = sqs_client.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=1, MaxNumberOfMessages=1
        )
        messages = _response.get("Messages", [])
        if not messages:
            LOG.info("no messages received from %s after 1 second", queue_url)

        for m in messages:
            body = m["Body"]
            # see https://www.mikulskibartosz.name/what-is-s3-test-event/
            if "s3:TestEvent" in body:
                continue

            assert "Records" in body, "Unexpected event received"

            doc = json.loads(body)
            events.extend(doc["Records"])
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

        assert len(events) >= min_events

    retry(collect_events, retries=timeout, sleep=0.01)

    return events


@pytest.fixture
def sqs_create_queue_with_client():
    queue_urls = []

    def factory(sqs_client, **kwargs):
        if "QueueName" not in kwargs:
            kwargs["QueueName"] = "test-queue-%s" % short_uid()

        response = sqs_client.create_queue(**kwargs)
        url = response["QueueUrl"]
        queue_urls.append((sqs_client, url))
        return url

    yield factory

    # cleanup
    for client, queue_url in queue_urls:
        try:
            client.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)


@pytest.mark.skipif(condition=TEST_S3_IMAGE, reason="SQS not enabled in S3 image")
class TestS3NotificationsToSQS:
    @markers.aws.validated
    def test_object_created_put(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:Put"])

        aws_client.s3.put_object(Bucket=s3_bucket, Key="my_key_0", Body="something")
        aws_client.s3.put_object(Bucket=s3_bucket, Key="my_key_1", Body="something else")

        # collect s3 events from SQS queue
        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=2)

        assert len(events) == 2, f"unexpected number of events in {events}"
        # order seems not be guaranteed - sort so we can rely on the order
        events.sort(key=lambda x: x["s3"]["object"]["size"])
        snapshot.match("receive_messages", {"messages": events})

    @markers.aws.validated
    def test_object_created_copy(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:Copy"])

        src_key = "src-dest-%s" % short_uid()
        dest_key = "key-dest-%s" % short_uid()

        aws_client.s3.put_object(Bucket=s3_bucket, Key=src_key, Body="something")

        assert not sqs_collect_s3_events(
            aws_client.sqs, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        aws_client.s3.copy_object(
            Bucket=s3_bucket,
            CopySource={"Bucket": s3_bucket, "Key": src_key},
            Key=dest_key,
        )

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"
        snapshot.match("receive_messages", {"messages": events})
        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectCreated:Copy"
        assert events[0]["s3"]["bucket"]["name"] == s3_bucket
        assert events[0]["s3"]["object"]["key"] == dest_key

    @markers.aws.validated
    def test_object_created_and_object_removed(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(
            s3_bucket, queue_url, ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        )

        src_key = f"src-dest-{short_uid()}"
        dest_key = f"key-dest-{short_uid()}"

        # event0 = PutObject
        aws_client.s3.put_object(Bucket=s3_bucket, Key=src_key, Body="something")
        # event1 = CopyObject
        aws_client.s3.copy_object(
            Bucket=s3_bucket,
            CopySource={"Bucket": s3_bucket, "Key": src_key},
            Key=dest_key,
        )
        # event3 = DeleteObject
        aws_client.s3.delete_object(Bucket=s3_bucket, Key=src_key)

        # collect events
        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 3)
        assert len(events) == 3, f"unexpected number of events in {events}"

        # order seems not be guaranteed - sort so we can rely on the order
        events.sort(key=lambda x: x["eventName"])

        snapshot.match("receive_messages", {"messages": events})

        assert events[1]["eventName"] == "ObjectCreated:Put"
        assert events[1]["s3"]["bucket"]["name"] == s3_bucket
        assert events[1]["s3"]["object"]["key"] == src_key

        assert events[0]["eventName"] == "ObjectCreated:Copy"
        assert events[0]["s3"]["bucket"]["name"] == s3_bucket
        assert events[0]["s3"]["object"]["key"] == dest_key

        assert events[2]["eventName"] == "ObjectRemoved:Delete"
        assert events[2]["s3"]["bucket"]["name"] == s3_bucket
        assert events[2]["s3"]["object"]["key"] == src_key

    @markers.aws.validated
    def test_delete_objects(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectRemoved:*"])

        key = "key-%s" % short_uid()

        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body="something")

        # event3 = DeleteObject
        aws_client.s3.delete_objects(
            Bucket=s3_bucket,
            Delete={
                "Objects": [{"Key": key}, {"Key": "dummy1"}, {"Key": "dummy2"}],
                "Quiet": True,
            },
        )

        # delete_objects behaves like it deletes non-existing objects as well -> also events are triggered
        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 3)
        assert len(events) == 3, f"unexpected number of events in {events}"
        events.sort(key=lambda x: x["s3"]["object"]["key"])

        snapshot.match("receive_messages", {"messages": events})
        assert events[2]["eventName"] == "ObjectRemoved:Delete"
        assert events[2]["s3"]["bucket"]["name"] == s3_bucket
        assert events[2]["s3"]["object"]["key"] == key

    @markers.aws.validated
    def test_object_created_complete_multipart_upload(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        tmpdir,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # setup fixture
        queue_url = sqs_create_queue()
        key = "test-key"

        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:*"])

        # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/s3.html#multipart-transfers
        config = TransferConfig(multipart_threshold=5 * KB, multipart_chunksize=1 * KB)

        file = tmpdir / "test-file.bin"
        data = b"1" * (6 * KB)  # create 6 kilobytes of ones
        file.write(data=data, mode="w")
        aws_client.s3.upload_file(
            Bucket=s3_bucket, Key=key, Filename=str(file.realpath()), Config=config
        )

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:CompleteMultipartUpload"
        assert events[0]["s3"]["bucket"]["name"] == s3_bucket
        assert events[0]["s3"]["object"]["key"] == key
        assert events[0]["s3"]["object"]["size"] == file.size()

    @markers.aws.validated
    def test_key_encoding(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # test for https://github.com/localstack/localstack/issues/2741

        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:*"])

        key = "a@b"
        key_encoded = "a%40b"
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body="something")

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=1)
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key_encoded

    @markers.aws.validated
    def test_object_created_put_with_presigned_url_upload(
        self,
        s3_bucket,
        s3_create_bucket_with_client,
        sqs_create_queue,
        sqs_create_queue_with_client,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
        aws_client_factory,
        secondary_region_name,
    ):
        """This test validates that pre-signed URL works with notification, and that the awsRegion field is the
        bucket's region"""
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.key_value("awsRegion"), priority=-1)

        queue_url = sqs_create_queue()
        key = "key-by-hostname"
        s3_client = aws_client_factory(
            config=Config(signature_version="s3v4"),
        ).s3

        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:*"])
        url = s3_client.generate_presigned_url(
            "put_object", Params={"Bucket": s3_bucket, "Key": key}
        )
        requests.put(url, data="something", verify=False)

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key

        # test with the bucket in a different region than the client
        s3_client_region_2 = aws_client_factory(region_name=secondary_region_name).s3
        bucket_name_region_2 = f"test-bucket-{short_uid()}"
        s3_create_bucket_with_client(
            s3_client=s3_client_region_2,
            Bucket=bucket_name_region_2,
            CreateBucketConfiguration={"LocationConstraint": secondary_region_name},
        )

        # the SQS queue needs to be in the same region as the S3 bucket
        sqs_client_region_2 = aws_client_factory(region_name=secondary_region_name).sqs
        queue_url_region_2 = sqs_create_queue_with_client(sqs_client_region_2)
        s3_create_sqs_bucket_notification(
            bucket_name=bucket_name_region_2,
            queue_url=queue_url_region_2,
            events=["s3:ObjectCreated:*"],
            sqs_client=sqs_client_region_2,
            s3_client=s3_client_region_2,
        )
        # still generate the presign URL with the default client, with the default region
        url_bucket_region_2 = s3_client_region_2.generate_presigned_url(
            "put_object", Params={"Bucket": bucket_name_region_2, "Key": key}
        )
        requests.put(url_bucket_region_2, data="something", verify=False)

        events = sqs_collect_s3_events(sqs_client_region_2, queue_url_region_2, 1)
        snapshot.match("receive_messages_region_2", {"messages": events})

    @markers.aws.validated
    def test_object_tagging_put_event(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectTagging:Put"])

        dest_key = f"key-dest-{short_uid()}"

        aws_client.s3.put_object(Bucket=s3_bucket, Key=dest_key, Body="FooBarBlitz")

        assert not sqs_collect_s3_events(
            aws_client.sqs, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        aws_client.s3.put_object_tagging(
            Bucket=s3_bucket,
            Key=dest_key,
            Tagging={
                "TagSet": [
                    {"Key": "swallow_type", "Value": "african"},
                ]
            },
        )

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Put"
        assert events[0]["s3"]["bucket"]["name"] == s3_bucket
        assert events[0]["s3"]["object"]["key"] == dest_key

    @markers.aws.validated
    def test_object_tagging_delete_event(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectTagging:Delete"])

        dest_key = "key-dest-%s" % short_uid()

        aws_client.s3.put_object(Bucket=s3_bucket, Key=dest_key, Body="FooBarBlitz")

        assert not sqs_collect_s3_events(
            aws_client.sqs, queue_url, 0, timeout=1
        ), "unexpected event triggered for put_object"

        aws_client.s3.put_object_tagging(
            Bucket=s3_bucket,
            Key=dest_key,
            Tagging={
                "TagSet": [
                    {"Key": "swallow_type", "Value": "african"},
                ]
            },
        )

        aws_client.s3.delete_object_tagging(
            Bucket=s3_bucket,
            Key=dest_key,
        )

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        assert len(events) == 1, f"unexpected number of events in {events}"
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Delete"
        assert events[0]["s3"]["bucket"]["name"] == s3_bucket
        assert events[0]["s3"]["object"]["key"] == dest_key

    @markers.aws.validated
    def test_xray_header(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        cleanups,
        snapshot,
        aws_client,
    ):
        # test for https://github.com/localstack/localstack/issues/3686

        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(
            snapshot.transform.key_value("MD5OfBody", reference_replacement=False)
        )

        # add boto hook
        def add_xray_header(request, **kwargs):
            request.headers["X-Amzn-Trace-Id"] = (
                "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
            )

        aws_client.s3.meta.events.register("before-send.s3.*", add_xray_header)
        # make sure the hook gets cleaned up after the test
        cleanups.append(
            lambda: aws_client.s3.meta.events.unregister("before-send.s3.*", add_xray_header)
        )

        key = "test-data"
        queue_url = sqs_create_queue()

        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectCreated:*"])

        # put an object where the bucket_name is in the path
        aws_client.s3.put_object(Bucket=s3_bucket, Key=key, Body="something")

        def get_messages():
            recv_messages = []
            resp = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["AWSTraceHeader"],
                MessageAttributeNames=["All"],
                VisibilityTimeout=0,
            )
            for m in resp["Messages"]:
                if "s3:TestEvent" in m["Body"]:
                    aws_client.sqs.delete_message(
                        QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"]
                    )
                    continue
                recv_messages.append(m)

            assert len(recv_messages) >= 1
            return recv_messages

        messages = retry(get_messages, retries=10)

        assert "AWSTraceHeader" in messages[0]["Attributes"]
        assert (
            messages[0]["Attributes"]["AWSTraceHeader"]
            == "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
        )
        snapshot.match("receive_messages", {"messages": messages})

    @markers.aws.validated
    def test_notifications_with_filter(
        self,
        s3_bucket,
        s3_create_sqs_bucket_notification,
        sqs_create_queue,
        snapshot,
        aws_client,
    ):
        # create test bucket and queue
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        snapshot.add_transformer(snapshot.transform.regex(queue_name, "<queue>"))
        snapshot.add_transformer(snapshot.transform.regex(s3_bucket, "<bucket>"))
        snapshot.add_transformer(snapshot.transform.s3_notifications_transformer())
        queue_arn = set_policy_for_queue(aws_client.sqs, queue_url, s3_bucket)

        events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:Delete"]
        filter_rules = {
            "FilterRules": [
                {"Name": "Prefix", "Value": "testupload/"},
                {"Name": "Suffix", "Value": "testfile.txt"},
            ]
        }
        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {
                        "Id": "id0001",
                        "QueueArn": queue_arn,
                        "Events": events,
                        "Filter": {"Key": filter_rules},
                    },
                    {
                        # Add second config to test fix https://github.com/localstack/localstack/issues/450
                        "Id": "id0002",
                        "QueueArn": queue_arn,
                        "Events": ["s3:ObjectTagging:*"],
                        "Filter": {"Key": filter_rules},
                    },
                ]
            },
        )

        # retrieve and check notification config
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("config", config)
        assert 2 == len(config["QueueConfigurations"])
        config = [c for c in config["QueueConfigurations"] if c.get("Events")][0]
        assert events == config["Events"]
        assert filter_rules == config["Filter"]["Key"]

        # upload file to S3 (this should NOT trigger a notification)
        test_key1 = "/testdata"
        test_data1 = b'{"test": "bucket_notification1"}'
        aws_client.s3.upload_fileobj(BytesIO(test_data1), s3_bucket, test_key1)

        # upload file to S3 (this should trigger a notification)
        test_key2 = "testupload/dir1/testfile.txt"
        test_data2 = b'{"test": "bucket_notification2"}'
        aws_client.s3.upload_fileobj(BytesIO(test_data2), s3_bucket, test_key2)

        # receive, assert, and delete message from SQS
        messages = sqs_collect_s3_events(aws_client.sqs, queue_url, 1)
        assert len(messages) == 1
        snapshot.match("message", messages[0])
        assert messages[0]["s3"]["object"]["key"] == test_key2
        assert messages[0]["s3"]["bucket"]["name"] == s3_bucket

        # delete notification config
        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration={}
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("config_empty", config)
        assert not config.get("QueueConfigurations")
        assert not config.get("TopicConfiguration")
        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"Id": "id123456", "QueueArn": queue_arn, "Events": [event]}
                ]
            },
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("config_updated", config)
        config = config["QueueConfigurations"][0]
        assert [event] == config["Events"]

        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        filter_rules = {"FilterRules": [{"Name": "Prefix", "Value": "testupload/"}]}
        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {
                        "Id": "id123456",
                        "QueueArn": queue_arn,
                        "Events": [event],
                        "Filter": {"Key": filter_rules},
                    }
                ]
            },
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("config_updated_filter", config)
        config = config["QueueConfigurations"][0]
        assert [event] == config["Events"]
        assert filter_rules == config["Filter"]["Key"]

    @markers.aws.validated
    def test_filter_rules_case_insensitive(self, s3_bucket, sqs_create_queue, snapshot, aws_client):
        id = short_uid()
        queue_url = sqs_create_queue(QueueName=f"my-queue-{id}")
        queue_attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        snapshot.add_transformer(snapshot.transform.key_value("Id", "id"))
        snapshot.add_transformer(snapshot.transform.regex(id, "<queue_id>"))
        cfg = {
            "QueueConfigurations": [
                {
                    "QueueArn": queue_attributes["Attributes"]["QueueArn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {
                            "FilterRules": [
                                {
                                    "Name": "suffix",
                                    "Value": ".txt",
                                },  # different casing should be normalized to Suffix/Prefix
                                {"Name": "PREFIX", "Value": "notif-"},
                            ]
                        }
                    },
                }
            ]
        }

        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration=cfg, SkipDestinationValidation=True
        )
        response = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        # verify casing of filter rule names

        rules = response["QueueConfigurations"][0]["Filter"]["Key"]["FilterRules"]
        valid = ["Prefix", "Suffix"]
        response["QueueConfigurations"][0]["Filter"]["Key"]["FilterRules"].sort(
            key=lambda x: x["Name"]
        )
        assert rules[0]["Name"] in valid
        assert rules[1]["Name"] in valid
        snapshot.match("bucket_notification_configuration", response)

    @markers.snapshot.skip_snapshot_verify(
        paths=["$..Error.ArgumentName", "$..Error.ArgumentValue"],
    )  # TODO: add to exception for ASF
    @markers.aws.validated
    def test_bucket_notification_with_invalid_filter_rules(
        self, s3_bucket, sqs_create_queue, snapshot, aws_client
    ):
        queue_url = sqs_create_queue()
        queue_attributes = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        cfg = {
            "QueueConfigurations": [
                {
                    "QueueArn": queue_attributes["Attributes"]["QueueArn"],
                    "Events": ["s3:ObjectCreated:*"],
                    "Filter": {
                        "Key": {"FilterRules": [{"Name": "INVALID", "Value": "does not matter"}]}
                    },
                }
            ]
        }
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket, NotificationConfiguration=cfg
            )
        snapshot.match("invalid_filter_name", e.value.response)

    @markers.aws.validated
    # AWS seems to return "ArgumentName" (without the number) if the request fails a basic verification
    # -  basically everything it can check isolated of the structure of the request
    # and then the "ArgumentNameX" (with the number) for each verification against the target services
    # e.g. queues not existing, no permissions etc.
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Error.ArgumentName1",
            "$..Error.ArgumentValue1",
            "$..Error.ArgumentName",
            "$..Error.ArgumentValue",
        ],
    )
    def test_invalid_sqs_arn(self, s3_bucket, account_id, snapshot, aws_client, region_name):
        config = {
            "QueueConfigurations": [
                {
                    "Id": "id123",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        }

        config["QueueConfigurations"][0]["QueueArn"] = "invalid-queue"
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

        # set valid but not-existing queue
        config["QueueConfigurations"][0]["QueueArn"] = arns.sqs_queue_arn(
            "my-queue", account_id=account_id, region_name=region_name
        )
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
            )
        snapshot.match("queue-does-not-exist", e.value.response)

        aws_client.s3.put_bucket_notification_configuration(
            Bucket=s3_bucket, NotificationConfiguration=config, SkipDestinationValidation=True
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=s3_bucket)
        snapshot.match("skip_destination_validation", config)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Error.ArgumentName",
            "$..Error.ArgumentValue",
            "$..Error.ArgumentName1",
            "$..Error.ArgumentValue1",
            "$..Error.ArgumentName2",
            "$..Error.ArgumentValue2",
            # AWS seems to validate all "form" verifications beforehand, so one error message is wrong
            "$..Error.Message",
        ],
    )
    def test_multiple_invalid_sqs_arns(
        self, s3_bucket, account_id, snapshot, aws_client, region_name
    ):
        config = {
            "QueueConfigurations": [
                {"Id": "id1", "Events": ["s3:ObjectCreated:*"], "QueueArn": "invalid_arn"},
                {
                    "Id": "id2",
                    "Events": ["s3:ObjectRemoved:*"],
                    "QueueArn": "invalid_arn_2",
                },
            ]
        }
        # multiple invalid arns
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
            )
        snapshot.match("two-queue-arns-invalid", e.value.response)

        # one invalid arn, one not existing
        config["QueueConfigurations"][0]["QueueArn"] = arns.sqs_queue_arn(
            "my-queue", account_id=account_id, region_name=region_name
        )
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
            )
        snapshot.match("one-queue-invalid-one-not-existent", e.value.response)

        # multiple not existing queues
        config["QueueConfigurations"][1]["QueueArn"] = arns.sqs_queue_arn(
            "my-queue-2", account_id=account_id, region_name=aws_client.s3.meta.region_name
        )
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=s3_bucket,
                NotificationConfiguration=config,
            )
        snapshot.match("multiple-queues-do-not-exist", e.value.response)

    @markers.aws.validated
    def test_object_put_acl(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # setup fixture
        aws_client.s3.delete_bucket_ownership_controls(Bucket=s3_bucket)
        aws_client.s3.delete_public_access_block(Bucket=s3_bucket)
        queue_url = sqs_create_queue()
        key_name = "my_key_acl"
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectAcl:Put"])

        aws_client.s3.put_object(Bucket=s3_bucket, Key=key_name, Body="something")
        list_bucket_output = aws_client.s3.list_buckets()
        owner = list_bucket_output["Owner"]

        # change the ACL to the default one, it should not send an Event. Use canned ACL first
        aws_client.s3.put_object_acl(Bucket=s3_bucket, Key=key_name, ACL="private")
        # change the ACL, it should not send an Event. Use canned ACL first
        aws_client.s3.put_object_acl(Bucket=s3_bucket, Key=key_name, ACL="public-read")
        # try changing ACL with Grant
        aws_client.s3.put_object_acl(
            Bucket=s3_bucket,
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
        aws_client.s3.put_object_acl(Bucket=s3_bucket, Key=key_name, AccessControlPolicy=acp)

        # collect s3 events from SQS queue
        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=3)

        assert len(events) == 3, f"unexpected number of events in {events}"
        # order seems not be guaranteed - sort so we can rely on the order
        events.sort(key=lambda x: x["eventTime"])
        snapshot.match("receive_messages", {"messages": events})

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..messages[1].requestParameters.sourceIPAddress",  # AWS IP address is different as its internal
        ],
    )
    def test_restore_object(
        self,
        s3_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # setup fixture
        queue_url = sqs_create_queue()
        key_name = "my_key_restore"
        s3_create_sqs_bucket_notification(s3_bucket, queue_url, ["s3:ObjectRestore:*"])

        # We set the StorageClass to Glacier Flexible Retrieval (formerly Glacier) as it's the only one allowing
        # Expedited retrieval Tier (with the Intelligent Access Archive tier)
        aws_client.s3.put_object(
            Bucket=s3_bucket, Key=key_name, Body="something", StorageClass="GLACIER"
        )

        aws_client.s3.restore_object(
            Bucket=s3_bucket,
            Key=key_name,
            RestoreRequest={
                "Days": 1,
                "GlacierJobParameters": {
                    "Tier": "Expedited",  # Set it as Expedited, it should be done within 1-5min
                },
            },
        )

        def _is_object_restored():
            resp = aws_client.s3.head_object(Bucket=s3_bucket, Key=key_name)
            assert 'ongoing-request="false"' in resp["Restore"]

        if is_aws_cloud():
            retries = 12
            sleep = 30
        else:
            retries = 3
            sleep = 1

        retry(_is_object_restored, retries=retries, sleep=sleep)

        # collect s3 events from SQS queue
        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=2)

        assert len(events) == 2, f"unexpected number of events in {events}"
        # order seems not be guaranteed - sort, so we can rely on the order
        events.sort(key=lambda x: x["eventTime"])
        snapshot.match("receive_messages", {"messages": events})

    @markers.aws.validated
    @pytest.mark.skipif(
        condition=is_v2_provider(),
        reason="Not implemented in Legacy provider",
    )
    def test_object_created_put_versioned(
        self, s3_bucket, sqs_create_queue, s3_create_sqs_bucket_notification, snapshot, aws_client
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        # setup fixture
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(
            s3_bucket, queue_url, ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
        )

        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Enabled"}
        )

        test_key = "test-key"
        # We snapshot all objects to snapshot their VersionId, to be sure the events correspond well to what we think
        # create first version
        obj_ver1 = aws_client.s3.put_object(Bucket=s3_bucket, Key=test_key, Body=b"data")
        snapshot.match("obj-ver1", obj_ver1)
        # create second version
        obj_ver2 = aws_client.s3.put_object(Bucket=s3_bucket, Key=test_key, Body=b"data-version2")
        snapshot.match("obj-ver2", obj_ver2)
        # delete the top most version, creating a DeleteMarker
        delete_marker = aws_client.s3.delete_object(Bucket=s3_bucket, Key=test_key)
        snapshot.match("delete-marker", delete_marker)
        # delete a specific version (Version1)
        delete_version = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=test_key, VersionId=obj_ver1["VersionId"]
        )
        snapshot.match("delete-version", delete_version)

        def _sort_events(_events: list[dict]) -> list[dict]:
            return sorted(
                _events,
                key=lambda x: (
                    x["eventName"],
                    x["s3"]["object"].get("eTag", ""),
                ),
            )

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=4)
        snapshot.match("message-versioning-active", _sort_events(events))

        # suspend the versioning
        aws_client.s3.put_bucket_versioning(
            Bucket=s3_bucket, VersioningConfiguration={"Status": "Suspended"}
        )
        # add a new object, which will have versionId = null
        add_null_version = aws_client.s3.put_object(
            Bucket=s3_bucket, Key=test_key, Body=b"data-version3"
        )
        snapshot.match("add-null-version", add_null_version)
        # delete the DeleteMarker
        del_delete_marker = aws_client.s3.delete_object(
            Bucket=s3_bucket, Key=test_key, VersionId=delete_marker["VersionId"]
        )
        snapshot.match("del-delete-marker", del_delete_marker)

        events = sqs_collect_s3_events(aws_client.sqs, queue_url, min_events=2)
        snapshot.match("message-versioning-suspended", _sort_events(events))
