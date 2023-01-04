import json
import logging
from io import BytesIO
from typing import TYPE_CHECKING, Dict, List, Protocol

import pytest
import requests
from boto3.s3.transfer import KB, TransferConfig
from botocore.exceptions import ClientError

from localstack.config import LEGACY_S3_PROVIDER
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition, retry

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
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag"]
    )
    def test_object_created_put(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

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
        # order seems not be guaranteed - sort so we can rely on the order
        events.sort(key=lambda x: x["s3"]["object"]["size"])
        snapshot.match("receive_messages", {"messages": events})
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
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag", "$..s3.object.versionId"]
    )
    def test_object_created_copy(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

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
        snapshot.match("receive_messages", {"messages": events})
        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectCreated:Copy"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=["$..s3.object.eTag", "$..s3.object.versionId", "$..s3.object.size"],
    )
    def test_object_created_and_object_removed(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

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

        # order seems not be guaranteed - sort so we can rely on the order
        events.sort(key=lambda x: x["eventName"])

        snapshot.match("receive_messages", {"messages": events})

        assert events[1]["eventName"] == "ObjectCreated:Put"
        assert events[1]["s3"]["bucket"]["name"] == bucket_name
        assert events[1]["s3"]["object"]["key"] == src_key

        assert events[0]["eventName"] == "ObjectCreated:Copy"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

        assert events[2]["eventName"] == "ObjectRemoved:Delete"
        assert events[2]["s3"]["bucket"]["name"] == bucket_name
        assert events[2]["s3"]["object"]["key"] == src_key

    @pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="Not implemented in old provider")
    @pytest.mark.aws_validated
    def test_delete_objects(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

        # setup fixture
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectRemoved:*"])

        key = "key-%s" % short_uid()

        s3_client.put_object(Bucket=bucket_name, Key=key, Body="something")

        # event3 = DeleteObject
        s3_client.delete_objects(
            Bucket=bucket_name,
            Delete={
                "Objects": [{"Key": key}, {"Key": "dummy1"}, {"Key": "dummy2"}],
                "Quiet": True,
            },
        )

        # delete_objects behaves like it deletes non-existing objects as well -> also events are triggered
        events = sqs_collect_s3_events(sqs_client, queue_url, 3)
        assert len(events) == 3, f"unexpected number of events in {events}"
        events.sort(key=lambda x: x["s3"]["object"]["key"])

        snapshot.match("receive_messages", {"messages": events})
        assert events[2]["eventName"] == "ObjectRemoved:Delete"
        assert events[2]["s3"]["bucket"]["name"] == bucket_name
        assert events[2]["s3"]["object"]["key"] == key

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag", "$..s3.object.versionId"]
    )
    def test_object_created_complete_multipart_upload(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        tmpdir,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

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
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:CompleteMultipartUpload"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == key
        assert events[0]["s3"]["object"]["size"] == file.size()

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag", "$..s3.object.versionId"]
    )
    def test_key_encoding(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        # test for https://github.com/localstack/localstack/issues/2741

        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])

        key = "a@b"
        key_encoded = "a%40b"
        s3_client.put_object(Bucket=bucket_name, Key=key, Body="something")

        events = sqs_collect_s3_events(sqs_client, queue_url, min_events=1)
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key_encoded

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag", "$..s3.object.versionId"]
    )
    def test_object_created_put_with_presigned_url_upload(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())

        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        key = "key-by-hostname"

        s3_create_sqs_bucket_notification(bucket_name, queue_url, ["s3:ObjectCreated:*"])
        url = s3_client.generate_presigned_url(
            "put_object", Params={"Bucket": bucket_name, "Key": key}
        )
        requests.put(url, data="something", verify=False)

        events = sqs_collect_s3_events(sqs_client, queue_url, 1)
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventName"] == "ObjectCreated:Put"
        assert events[0]["s3"]["object"]["key"] == key

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=[
            "$..s3.object.eTag",
            "$..s3.object.versionId",
            "$..s3.object.size",
            "$..s3.object.sequencer",
            "$..eventVersion",
        ],
    )
    def test_object_tagging_put_event(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

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
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Put"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=[
            "$..s3.object.eTag",
            "$..s3.object.versionId",
            "$..s3.object.size",
            "$..s3.object.sequencer",
            "$..eventVersion",
        ],
    )
    def test_object_tagging_delete_event(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(snapshot.transform.jsonpath("$..s3.object.key", "object-key"))

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
        snapshot.match("receive_messages", {"messages": events})

        assert events[0]["eventSource"] == "aws:s3"
        assert events[0]["eventName"] == "ObjectTagging:Delete"
        assert events[0]["s3"]["bucket"]["name"] == bucket_name
        assert events[0]["s3"]["object"]["key"] == dest_key

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER, paths=["$..s3.object.eTag", "$..s3.object.versionId"]
    )
    def test_xray_header(
        self,
        s3_client,
        sqs_client,
        s3_create_bucket,
        sqs_create_queue,
        s3_create_sqs_bucket_notification,
        cleanups,
        snapshot,
    ):
        # test for https://github.com/localstack/localstack/issues/3686

        snapshot.add_transformer(snapshot.transform.sqs_api())
        snapshot.add_transformer(snapshot.transform.s3_api())
        snapshot.add_transformer(
            snapshot.transform.key_value("MD5OfBody", reference_replacement=False)
        )

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

        def get_messages():
            recv_messages = []
            resp = sqs_client.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["AWSTraceHeader"],
                MessageAttributeNames=["All"],
                VisibilityTimeout=0,
            )
            for m in resp["Messages"]:
                if "s3:TestEvent" in m["Body"]:
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=[
            "$..QueueConfigurations..Filter",
            "$..s3.object.eTag",
            "$..s3.object.versionId",
        ],
    )
    def test_notifications_with_filter(
        self,
        s3_client,
        s3_create_bucket,
        sqs_client,
        s3_create_sqs_bucket_notification,
        sqs_create_queue,
        snapshot,
    ):
        # create test bucket and queue
        bucket_name = f"notification-bucket-{short_uid()}"
        s3_create_bucket(Bucket=bucket_name)
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        snapshot.add_transformer(snapshot.transform.regex(queue_name, "<queue>"))
        snapshot.add_transformer(snapshot.transform.regex(bucket_name, "<bucket>"))
        snapshot.add_transformer(snapshot.transform.s3_notifications_transformer())
        queue_arn = set_policy_for_queue(sqs_client, queue_url, bucket_name)

        events = ["s3:ObjectCreated:*", "s3:ObjectRemoved:Delete"]
        filter_rules = {
            "FilterRules": [
                {"Name": "Prefix", "Value": "testupload/"},
                {"Name": "Suffix", "Value": "testfile.txt"},
            ]
        }
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
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
        config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("config", config)
        assert 2 == len(config["QueueConfigurations"])
        config = [c for c in config["QueueConfigurations"] if c.get("Events")][0]
        assert events == config["Events"]
        assert filter_rules == config["Filter"]["Key"]

        # upload file to S3 (this should NOT trigger a notification)
        test_key1 = "/testdata"
        test_data1 = b'{"test": "bucket_notification1"}'
        s3_client.upload_fileobj(BytesIO(test_data1), bucket_name, test_key1)

        # upload file to S3 (this should trigger a notification)
        test_key2 = "testupload/dir1/testfile.txt"
        test_data2 = b'{"test": "bucket_notification2"}'
        s3_client.upload_fileobj(BytesIO(test_data2), bucket_name, test_key2)

        # receive, assert, and delete message from SQS
        messages = sqs_collect_s3_events(sqs_client, queue_url, 1)
        assert len(messages) == 1
        snapshot.match("message", messages[0])
        assert messages[0]["s3"]["object"]["key"] == test_key2
        assert messages[0]["s3"]["bucket"]["name"] == bucket_name

        # delete notification config
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration={}
        )
        config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("config_empty", config)
        assert not config.get("QueueConfigurations")
        assert not config.get("TopicConfiguration")
        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"Id": "id123456", "QueueArn": queue_arn, "Events": [event]}
                ]
            },
        )
        config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("config_updated", config)
        config = config["QueueConfigurations"][0]
        assert [event] == config["Events"]

        # put notification config with single event type
        event = "s3:ObjectCreated:*"
        filter_rules = {"FilterRules": [{"Name": "Prefix", "Value": "testupload/"}]}
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
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
        config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("config_updated_filter", config)
        config = config["QueueConfigurations"][0]
        assert [event] == config["Events"]
        assert filter_rules == config["Filter"]["Key"]

    @pytest.mark.aws_validated
    def test_filter_rules_case_insensitive(
        self, s3_client, s3_create_bucket, sqs_create_queue, sqs_client, snapshot
    ):
        bucket_name = s3_create_bucket()
        id = short_uid()
        queue_url = sqs_create_queue(QueueName=f"my-queue-{id}")
        queue_attributes = sqs_client.get_queue_attributes(
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

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration=cfg, SkipDestinationValidation=True
        )
        response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        # verify casing of filter rule names

        rules = response["QueueConfigurations"][0]["Filter"]["Key"]["FilterRules"]
        valid = ["Prefix", "Suffix"]
        response["QueueConfigurations"][0]["Filter"]["Key"]["FilterRules"].sort(
            key=lambda x: x["Name"]
        )
        assert rules[0]["Name"] in valid
        assert rules[1]["Name"] in valid
        snapshot.match("bucket_notification_configuration", response)

    @pytest.mark.skip_snapshot_verify(
        condition=lambda: not LEGACY_S3_PROVIDER,
        paths=["$..Error.ArgumentName", "$..Error.ArgumentValue"],
    )  # TODO: add to exception for ASF
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: LEGACY_S3_PROVIDER,
        paths=["$..Error.RequestID"],
    )
    @pytest.mark.aws_validated
    def test_bucket_notification_with_invalid_filter_rules(
        self, s3_create_bucket, sqs_create_queue, sqs_client, s3_client, snapshot
    ):
        bucket_name = s3_create_bucket()
        queue_url = sqs_create_queue()
        queue_attributes = sqs_client.get_queue_attributes(
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
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name, NotificationConfiguration=cfg
            )
        snapshot.match("invalid_filter_name", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skipif(condition=LEGACY_S3_PROVIDER, reason="no validation implemented")
    @pytest.mark.skip_snapshot_verify(
        condition=lambda: not LEGACY_S3_PROVIDER,
        paths=[
            "$..Error.ArgumentName1",
            "$..Error.ArgumentValue1",
            "$..Error.ArgumentName",
            "$..Error.ArgumentValue",
        ],
    )
    def test_invalid_sqs_arn(self, s3_client, s3_create_bucket, account_id, snapshot):
        bucket_name = s3_create_bucket()
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
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
                SkipDestinationValidation=False,
            )
        snapshot.match("invalid_not_skip", e.value.response)

        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
                SkipDestinationValidation=True,
            )
        snapshot.match("invalid_skip", e.value.response)

        # set valid but not-existing queue
        config["QueueConfigurations"][0][
            "QueueArn"
        ] = f"{arns.sqs_queue_arn('my-queue', account_id=account_id)}"
        with pytest.raises(ClientError) as e:
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
            )
        snapshot.match("queue-does-not-exist", e.value.response)

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration=config, SkipDestinationValidation=True
        )
        config = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("skip_destination_validation", config)
