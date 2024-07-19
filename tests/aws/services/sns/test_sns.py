import base64
import contextlib
import json
import logging
import queue
import random
import time
from io import BytesIO
from operator import itemgetter

import pytest
import requests
import xmltodict
from botocore.auth import SigV4Auth
from botocore.exceptions import ClientError
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from pytest_httpserver import HTTPServer
from werkzeug import Response

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.constants import (
    AWS_REGION_US_EAST_1,
)
from localstack.services.sns.constants import (
    PLATFORM_ENDPOINT_MSGS_ENDPOINT,
    SMS_MSGS_ENDPOINT,
    SUBSCRIPTION_TOKENS_ENDPOINT,
)
from localstack.services.sns.provider import SnsProvider
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.config import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.aws.arns import parse_arn, sqs_queue_arn
from localstack.utils.net import wait_for_port_closed, wait_for_port_open
from localstack.utils.strings import short_uid, to_bytes, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import check_expected_lambda_log_events_length
from tests.aws.services.lambda_.functions import lambda_integration
from tests.aws.services.lambda_.test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_PYTHON_ECHO

LOG = logging.getLogger(__name__)

PUBLICATION_TIMEOUT = 0.500
PUBLICATION_RETRIES = 4


@pytest.fixture(autouse=True)
def sns_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.sns_api())


@pytest.fixture
def sns_create_platform_application(aws_client):
    platform_applications = []

    def factory(**kwargs):
        if "Name" not in kwargs:
            kwargs["Name"] = f"platform-app-{short_uid()}"
        response = aws_client.sns.create_platform_application(**kwargs)
        platform_applications.append(response["PlatformApplicationArn"])
        return response

    yield factory

    for platform_application in platform_applications:
        endpoints = aws_client.sns.list_endpoints_by_platform_application(
            PlatformApplicationArn=platform_application
        )
        for endpoint in endpoints["Endpoints"]:
            try:
                aws_client.sns.delete_endpoint(EndpointArn=endpoint["EndpointArn"])
            except Exception as e:
                LOG.debug(
                    "Error cleaning up platform endpoint '%s' for platform app '%s': %s",
                    endpoint["EndpointArn"],
                    platform_application,
                    e,
                )
        try:
            aws_client.sns.delete_platform_application(PlatformApplicationArn=platform_application)
        except Exception as e:
            LOG.debug("Error cleaning up platform application '%s': %s", platform_application, e)


class TestSNSTopicCrud:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.get-topic-attrs.Attributes.DeliveryPolicy",
            "$.get-topic-attrs.Attributes.EffectiveDeliveryPolicy",
            "$.get-topic-attrs.Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
        ]
    )
    def test_create_topic_with_attributes(self, sns_create_topic, snapshot, aws_client):
        create_topic = sns_create_topic(
            Name="topictest.fifo",
            Attributes={
                "DisplayName": "TestTopic",
                "SignatureVersion": "2",
                "FifoTopic": "true",
            },
        )
        topic_arn = create_topic["TopicArn"]

        get_attrs_resp = aws_client.sns.get_topic_attributes(
            TopicArn=topic_arn,
        )
        snapshot.match("get-topic-attrs", get_attrs_resp)

        with pytest.raises(ClientError) as e:
            wrong_topic_arn = f"{topic_arn[:-8]}{short_uid()}"
            aws_client.sns.get_topic_attributes(TopicArn=wrong_topic_arn)

        snapshot.match("get-attrs-nonexistent-topic", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.get_topic_attributes(TopicArn="test-topic")

        snapshot.match("get-attrs-malformed-topic", e.value.response)

    @markers.aws.validated
    def test_tags(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]
        with pytest.raises(ClientError) as exc:
            aws_client.sns.tag_resource(
                ResourceArn=topic_arn,
                Tags=[
                    {"Key": "k1", "Value": "v1"},
                    {"Key": "k2", "Value": "v2"},
                    {"Key": "k2", "Value": "v2"},
                ],
            )
        snapshot.match("duplicate-key-error", exc.value.response)

        aws_client.sns.tag_resource(
            ResourceArn=topic_arn,
            Tags=[
                {"Key": "k1", "Value": "v1"},
                {"Key": "k2", "Value": "v2"},
            ],
        )

        tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
        # could not figure out the logic for tag order in AWS, so resorting to sorting it manually in place
        tags["Tags"].sort(key=itemgetter("Key"))
        snapshot.match("list-created-tags", tags)

        aws_client.sns.untag_resource(ResourceArn=topic_arn, TagKeys=["k1"])
        tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
        snapshot.match("list-after-delete-tags", tags)

        # test update tag
        aws_client.sns.tag_resource(ResourceArn=topic_arn, Tags=[{"Key": "k2", "Value": "v2b"}])
        tags = aws_client.sns.list_tags_for_resource(ResourceArn=topic_arn)
        snapshot.match("list-after-update-tags", tags)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.get-topic-attrs.Attributes.DeliveryPolicy",
            "$.get-topic-attrs.Attributes.EffectiveDeliveryPolicy",
            "$.get-topic-attrs.Attributes.Policy.Statement..Action",
            # SNS:Receive is added by moto but not returned in AWS
        ]
    )
    def test_create_topic_test_arn(self, sns_create_topic, snapshot, aws_client, account_id):
        topic_name = "topic-test-create"
        response = sns_create_topic(Name=topic_name)
        snapshot.match("create-topic", response)
        topic_arn = response["TopicArn"]
        topic_arn_params = topic_arn.split(":")
        testutil.response_arn_matches_partition(aws_client.sns, topic_arn)
        # we match the response but need to be sure the resource name is the same
        assert topic_arn_params[5] == topic_name

        if not is_aws_cloud():
            assert topic_arn_params[4] == account_id

        topic_attrs = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("get-topic-attrs", topic_attrs)

        response = aws_client.sns.delete_topic(TopicArn=topic_arn)
        snapshot.match("delete-topic", response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic-not-exists", e.value.response)

    @markers.aws.validated
    def test_create_duplicate_topic_with_more_tags(self, sns_create_topic, snapshot, aws_client):
        topic_name = "test-duplicated-topic-more-tags"
        sns_create_topic(Name=topic_name)

        with pytest.raises(ClientError) as e:
            aws_client.sns.create_topic(Name=topic_name, Tags=[{"Key": "key1", "Value": "value1"}])

        snapshot.match("exception-duplicate", e.value.response)

    @markers.aws.validated
    def test_create_duplicate_topic_check_idempotency(self, sns_create_topic, snapshot):
        topic_name = f"test-{short_uid()}"
        tags = [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}]
        kwargs = [
            {"Tags": tags},  # to create the same topic again with same tags
            {"Tags": [tags[0]]},  # to create the same topic again with one of the tags from above
            {"Tags": []},  # to create the same topic again with no tags
        ]

        # create topic with two tags
        response = sns_create_topic(Name=topic_name, Tags=tags)
        snapshot.match("response-created", response)

        for index, arg in enumerate(kwargs):
            response = sns_create_topic(Name=topic_name, **arg)
            # we check in the snapshot that they all have the same <resource:1> tag (original topic)
            snapshot.match(f"response-same-arn-{index}", response)

    @markers.aws.validated
    def test_create_topic_after_delete_with_new_tags(self, sns_create_topic, snapshot, aws_client):
        topic_name = f"test-{short_uid()}"
        topic = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "pqr"}])
        snapshot.match("topic-0", topic)
        aws_client.sns.delete_topic(TopicArn=topic["TopicArn"])

        topic1 = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "abc"}])
        snapshot.match("topic-1", topic1)


class TestSNSPublishCrud:
    """
    This class contains tests related to the global `Publish` validation, not tied to a particular kind of subscription
    """

    @markers.aws.validated
    def test_publish_by_path_parameters(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        aws_http_client_factory,
        snapshot,
        aws_client,
        region_name,
    ):
        message = "test message direct post request"
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        client = aws_http_client_factory(
            "sns",
            signer_factory=SigV4Auth,
            region=region_name,
            aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )

        if is_aws_cloud():
            endpoint_url = f"https://sns.{region_name}.amazonaws.com"
        else:
            endpoint_url = config.internal_service_url()

        response = client.post(
            endpoint_url,
            params={
                "Action": "Publish",
                "Version": "2010-03-31",
                "TopicArn": topic_arn,
                "Message": message,
            },
        )

        json_response = xmltodict.parse(response.content)
        json_response["PublishResponse"].pop("@xmlns")
        json_response["PublishResponse"]["ResponseMetadata"]["HTTPStatusCode"] = (
            response.status_code
        )
        json_response["PublishResponse"]["ResponseMetadata"]["HTTPHeaders"] = dict(response.headers)
        snapshot.match("post-request", json_response)

        assert response.status_code == 200
        assert b"<PublishResponse" in response.content

        rs = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5
        )
        snapshot.match("messages", rs)
        msg_body = json.loads(rs["Messages"][0]["Body"])
        assert msg_body["TopicArn"] == topic_arn
        assert msg_body["Message"] == message

    @markers.aws.validated
    def test_publish_wrong_arn_format(self, snapshot, aws_client):
        message = "Good news everyone!"
        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message=message, TopicArn="randomstring")

        snapshot.match("invalid-topic-arn", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message=message, TopicArn="randomstring:1")

        snapshot.match("invalid-topic-arn-1", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message=message, TopicArn="")

        snapshot.match("empty-topic", e.value.response)

    @markers.aws.validated
    def test_publish_message_by_target_arn(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        # using an SQS subscription to test TopicArn/TargetArn as it is easier to check against AWS
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        aws_client.sns.publish(TopicArn=topic_arn, Message="test-msg-1")

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )

        snapshot.match("receive-topic-arn", response)

        message = response["Messages"][0]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])

        # publish with TargetArn instead of TopicArn
        aws_client.sns.publish(TargetArn=topic_arn, Message="test-msg-2")

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        snapshot.match("receive-target-arn", response)

    @markers.aws.validated
    def test_publish_message_before_subscribe_topic(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        rs = aws_client.sns.publish(
            TopicArn=topic_arn, Subject="test-subject-before-sub", Message="test_message_before"
        )
        snapshot.match("publish-before-subscribing", rs)

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message_subject = "test-subject-after-sub"
        message_body = "test_message_after"

        rs = aws_client.sns.publish(
            TopicArn=topic_arn, Subject=message_subject, Message=message_body
        )
        snapshot.match("publish-after-subscribing", rs)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5
        )
        # nothing was subscribing to the topic, so the first message is lost
        snapshot.match("receive-messages", response)

    @markers.aws.validated
    def test_unknown_topic_publish(self, sns_create_topic, snapshot, aws_client):
        # create topic to get the basic arn structure
        # otherwise you get InvalidClientTokenId exception because of account id
        topic_arn = sns_create_topic()["TopicArn"]
        # append to get an unknown topic
        fake_arn = f"{topic_arn}-fake"
        message = "This is a test message"

        # test to send a message with no subscribers
        response = aws_client.sns.publish(TopicArn=topic_arn, Message=message)
        snapshot.match("success", response)

        # test to send to a nonexistent topic
        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(TopicArn=fake_arn, Message=message)

        snapshot.match("error", e.value.response)

    @markers.aws.validated
    def test_topic_publish_another_region(
        self, sns_create_topic, snapshot, aws_client, aws_client_factory, secondary_region_name
    ):
        # create the topic in the default region, so that it's easier to clean up with the fixture
        topic_arn = sns_create_topic()["TopicArn"]

        # create a client in another region
        sns_client_region_2 = aws_client_factory.get_client(
            service_name="sns",
            region_name=secondary_region_name,
        )

        message = "This is a test message"

        # test to send a message with the client from the same region
        response = aws_client.sns.publish(TopicArn=topic_arn, Message=message)
        snapshot.match("success", response)

        # test to send from the second region client
        with pytest.raises(ClientError) as e:
            sns_client_region_2.publish(TopicArn=topic_arn, Message=message)

        snapshot.match("error", e.value.response)

        # test to send batch from the second region client
        with pytest.raises(ClientError) as e:
            sns_client_region_2.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": message,
                    }
                ],
            )

        snapshot.match("error-batch", e.value.response)

    @markers.aws.validated
    def test_publish_non_existent_target(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]
        account_id = parse_arn(topic_arn)["account"]
        with pytest.raises(ClientError) as ex:
            aws_client.sns.publish(
                TargetArn=f"arn:aws:sns:us-east-1:{account_id}:endpoint/APNS/abcdef/0f7d5971-aa8b-4bd5-b585-0826e9f93a66",
                Message="This is a push notification",
            )
        snapshot.match("non-existent-endpoint", ex.value.response)

    @markers.aws.validated
    def test_publish_with_empty_subject(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]

        # Publish without subject
        rs = aws_client.sns.publish(
            TopicArn=topic_arn, Message=json.dumps({"message": "test_publish"})
        )
        snapshot.match("response-without-subject", rs)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Subject="",
                Message=json.dumps({"message": "test_publish"}),
            )

        snapshot.match("response-with-empty-subject", e.value.response)

    @markers.aws.validated
    def test_empty_sns_message(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message="", TopicArn=topic_arn)

        snapshot.match("empty-msg-error", e.value.response)

        queue_attrs = aws_client.sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        snapshot.match("queue-attrs", queue_attrs)

    @markers.aws.validated
    def test_publish_too_long_message(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]
        # simulate payload over 256kb
        message = "This is a test message" * 12000

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(TopicArn=topic_arn, Message=message)

        snapshot.match("error", e.value.response)

        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["Error"]["Message"] == "Invalid parameter: Message too long"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    @markers.aws.validated
    def test_message_structure_json_exc(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]
        # TODO: add batch

        # missing `default` key for the JSON
        with pytest.raises(ClientError) as e:
            message = json.dumps({"sqs": "Test message"})
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=message,
                MessageStructure="json",
            )
        snapshot.match("missing-default-key", e.value.response)

        # invalid JSON
        with pytest.raises(ClientError) as e:
            message = '{"default": "This is a default message"} }'
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=message,
                MessageStructure="json",
            )
        snapshot.match("invalid-json", e.value.response)

        # duplicate keys: from SNS docs, should fail but does work
        # https://docs.aws.amazon.com/sns/latest/api/API_Publish.html
        # `Duplicate keys are not allowed.`
        message = '{"default": "This is a default message", "default": "Duplicate"}'
        resp = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageStructure="json",
        )
        snapshot.match("duplicate-json-keys", resp)

        with pytest.raises(ClientError) as e:
            message = json.dumps({"default": {"object": "test"}})
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message=message,
                MessageStructure="json",
            )
        snapshot.match("key-is-not-string", e.value.response)


class TestSNSSubscriptionCrud:
    @markers.aws.validated
    def test_subscribe_with_invalid_protocol(self, sns_create_topic, sns_subscription, snapshot):
        topic_arn = sns_create_topic()["TopicArn"]

        with pytest.raises(ClientError) as e:
            sns_subscription(
                TopicArn=topic_arn, Protocol="test-protocol", Endpoint="localstack@yopmail.com"
            )

        snapshot.match("exception", e.value.response)

    @markers.aws.validated
    def test_unsubscribe_from_non_existing_subscription(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        # unsubscribing a second time
        response = aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        snapshot.match("empty-unsubscribe", response)

    @markers.aws.validated
    def test_create_subscriptions_with_attributes(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        snapshot,
        aws_client,
        sns_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        with pytest.raises(ClientError) as e:
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="sqs",
                Endpoint=queue_arn,
                Attributes={
                    "RawMessageDelivery": "wrongvalue",  # set an weird case value, SNS will lower it
                    "FilterPolicyScope": "MessageBody",
                    "FilterPolicy": "",
                },
                ReturnSubscriptionArn=True,
            )
        snapshot.match("subscribe-wrong-attr", e.value.response)

        subscribe_resp = sns_subscription(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
            Attributes={
                "RawMessageDelivery": "TrUe",  # set an weird case value, SNS will lower it
                "FilterPolicyScope": "MessageBody",
                "FilterPolicy": "",
            },
            ReturnSubscriptionArn=True,
        )
        snapshot.match("subscribe", subscribe_resp)

        get_attrs_resp = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscribe_resp["SubscriptionArn"]
        )
        snapshot.match("get-attrs", get_attrs_resp)

        with pytest.raises(ClientError) as e:
            wrong_sub_arn = f"{subscribe_resp['SubscriptionArn'][:-8]}{short_uid()}"
            aws_client.sns.get_subscription_attributes(SubscriptionArn=wrong_sub_arn)

        snapshot.match("get-attrs-nonexistent-sub", e.value.response)

    @markers.aws.validated
    def test_not_found_error_on_set_subscription_attributes(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)
        subscription = sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
        snapshot.match("sub", subscription)
        subscription_arn = subscription["SubscriptionArn"]

        response = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        subscription_attributes = response["Attributes"]
        snapshot.match("sub-attrs", response)

        assert subscription_attributes["SubscriptionArn"] == subscription_arn

        subscriptions_by_topic = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        snapshot.match("subscriptions-for-topic-before-unsub", subscriptions_by_topic)
        assert len(subscriptions_by_topic["Subscriptions"]) == 1

        aws_client.sns.unsubscribe(SubscriptionArn=subscription_arn)

        def check_subscription_deleted():
            try:
                # AWS doesn't give NotFound error on GetSubscriptionAttributes for a while, might be cached
                aws_client.sns.set_subscription_attributes(
                    SubscriptionArn=subscription_arn,
                    AttributeName="RawMessageDelivery",
                    AttributeValue="true",
                )
                raise Exception("Subscription is not deleted")
            except ClientError as e:
                assert e.response["Error"]["Code"] == "NotFound"
                assert e.response["ResponseMetadata"]["HTTPStatusCode"] == 404
                snapshot.match("sub-not-found", e.response)

        retry(check_subscription_deleted, retries=10, sleep_before=0.2, sleep=3)
        subscriptions_by_topic = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        snapshot.match("subscriptions-for-topic-after-unsub", subscriptions_by_topic)
        assert len(subscriptions_by_topic["Subscriptions"]) == 0

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.invalid-json-redrive-policy.Error.Message",  # message contains java trace in AWS, assert instead
            "$.invalid-json-filter-policy.Error.Message",  # message contains java trace in AWS, assert instead
        ]
    )
    def test_validate_set_sub_attributes(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        sub_arn = subscription["SubscriptionArn"]

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="FakeAttribute",
                AttributeValue="test-value",
            )
        snapshot.match("fake-attribute", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="RawMessageDelivery",
                AttributeValue="test-ValUe",
            )
        snapshot.match("raw-message-wrong-value", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="RawMessageDelivery",
                AttributeValue="",
            )
        snapshot.match("raw-message-empty-value", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="RedrivePolicy",
                AttributeValue=json.dumps({"deadLetterTargetArn": "fake-arn"}),
            )
        snapshot.match("fake-arn-redrive-policy", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="RedrivePolicy",
                AttributeValue="{invalidjson}",
            )
        snapshot.match("invalid-json-redrive-policy", e.value.response)
        assert e.value.response["Error"]["Message"].startswith(
            "Invalid parameter: RedrivePolicy: failed to parse JSON."
        )

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=sub_arn,
                AttributeName="FilterPolicy",
                AttributeValue="{invalidjson}",
            )
        snapshot.match("invalid-json-filter-policy", e.value.response)
        assert e.value.response["Error"]["Message"].startswith(
            "Invalid parameter: FilterPolicy: failed to parse JSON."
        )

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$.invalid-token.Error.Message"]  # validate the token shape
    )
    def test_sns_confirm_subscription_wrong_token(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]

        with pytest.raises(ClientError) as e:
            wrong_topic = topic_arn[:-1] + "i"
            aws_client.sns.confirm_subscription(
                TopicArn=wrong_topic,
                Token="51b2ff3edb475b7d91550e0ab6edf0c1de2a34e6ebaf6c2262a001bcb7e051c43aa00022ceecce70bd2a67b2042da8d8eb47fef7a4e4e942d23e7fa56146b9ee35da040b4b8af564cc4184a7391c834cb75d75c22981f776ad1ce8805e9bab29da2329985337bb8095627907b46c8577c8440556b6f86582a954758026f41fc62041c4b3f67b0f5921232b5dae5aaca1",
            )

        snapshot.match("topic-not-exists", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token="randomtoken")

        snapshot.match("invalid-token", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.confirm_subscription(
                TopicArn=topic_arn,
                Token="51b2ff3edb475b7d91550e0ab6edf0c1de2a34e6ebaf6c2262a001bcb7e051c43aa00022ceecce70bd2a67b2042da8d8eb47fef7a4e4e942d23e7fa56146b9ee35da040b4b8af564cc4184a7391c834cb75d75c22981f776ad1ce8805e9bab29da2329985337bb8095627907b46c8577c8440556b6f86582a954758026f41fc62041c4b3f67b0f5921232b5dae5aaca1",
            )

        snapshot.match("token-not-exists", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=["$.list-subscriptions.Subscriptions"],
        # there could be cleanup issues and don't want to flake, manually assert
    )
    def test_list_subscriptions(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_subscription,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("NextToken"))
        topic = sns_create_topic()
        topic_arn = topic["TopicArn"]
        snapshot.match("create-topic-1", topic)
        topic_2 = sns_create_topic()
        topic_arn_2 = topic_2["TopicArn"]
        snapshot.match("create-topic-2", topic_2)
        sorting_list = []
        for i in range(3):
            queue_url = sqs_create_queue()
            queue_arn = sqs_get_queue_arn(queue_url)
            subscription = sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
            snapshot.match(f"sub-topic-1-{i}", subscription)
            sorting_list.append((topic_arn, queue_arn))
        for i in range(3):
            queue_url = sqs_create_queue()
            queue_arn = sqs_get_queue_arn(queue_url)
            subscription = sns_subscription(
                TopicArn=topic_arn_2, Protocol="sqs", Endpoint=queue_arn
            )
            snapshot.match(f"sub-topic-2-{i}", subscription)
            sorting_list.append((topic_arn_2, queue_arn))

        list_subs = aws_client.sns.list_subscriptions()
        all_subs = list_subs["Subscriptions"]
        if list_subs.get("NextToken"):
            while next_token := list_subs.get("NextToken"):
                list_subs = aws_client.sns.list_subscriptions(NextToken=next_token)
                all_subs.extend(list_subs["Subscriptions"])

        all_subs.sort(key=lambda x: sorting_list.index((x["TopicArn"], x["Endpoint"])))
        list_subs["Subscriptions"] = all_subs
        snapshot.match("list-subscriptions-aggregated", list_subs)

        assert all((sub["TopicArn"], sub["Endpoint"]) in sorting_list for sub in all_subs)

    @markers.aws.validated
    def test_list_subscriptions_by_topic_pagination(
        self, sns_create_topic, sns_subscription, snapshot, aws_client
    ):
        # ordering of the listing seems to be not consistent, so we can transform its value
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value("Endpoint"),
                snapshot.transform.key_value("NextToken"),
            ]
        )

        base_phone_number = "+12312312"
        topic_arn = sns_create_topic()["TopicArn"]
        for phone_suffix in range(101):
            phone_number = f"{base_phone_number}{phone_suffix}"
            sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=phone_number)

        response = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        # not snapshotting the results, it contains 100 entries
        assert "NextToken" in response
        # seems to be b64 encoded
        assert base64.b64decode(response["NextToken"])
        assert len(response["Subscriptions"]) == 100
        # keep the page 1 subscriptions ARNs
        page_1_subs = {sub["SubscriptionArn"] for sub in response["Subscriptions"]}

        response = aws_client.sns.list_subscriptions_by_topic(
            TopicArn=topic_arn, NextToken=response["NextToken"]
        )
        snapshot.match("list-sub-per-topic-page-2", response)
        assert "NextToken" not in response
        assert len(response["Subscriptions"]) == 1
        # assert that the last Subscription is not present in page 1
        assert response["Subscriptions"][0]["SubscriptionArn"] not in page_1_subs

        response = aws_client.sns.list_subscriptions()
        # not snapshotting because there might be subscriptions outside the topic, this is all the requester subs
        assert "NextToken" in response
        assert len(response["Subscriptions"]) <= 100

    @markers.aws.validated
    def test_subscribe_idempotency(
        self, aws_client, sns_create_topic, sqs_create_queue, sqs_get_queue_arn, snapshot
    ):
        """
        Test the idempotency of SNS subscribe calls for a given endpoint and its attributes
        """
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        queue_arn = sqs_get_queue_arn(queue_url)

        def subscribe_queue_to_topic(attributes: dict = None) -> dict:
            kwargs = {}
            if attributes is not None:
                kwargs["Attributes"] = attributes
            response = aws_client.sns.subscribe(
                TopicArn=topic_arn,
                Protocol="sqs",
                Endpoint=queue_arn,
                ReturnSubscriptionArn=True,
                **kwargs,
            )
            return response

        subscribe_resp = subscribe_queue_to_topic(
            {
                "RawMessageDelivery": "true",
            }
        )
        snapshot.match("subscribe", subscribe_resp)

        get_attrs_resp = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscribe_resp["SubscriptionArn"]
        )
        snapshot.match("get-sub-attrs", get_attrs_resp)

        subscribe_resp = subscribe_queue_to_topic(
            {
                "RawMessageDelivery": "true",
            }
        )
        snapshot.match("subscribe-exact-same-raw", subscribe_resp)

        subscribe_resp = subscribe_queue_to_topic(
            {
                "RawMessageDelivery": "true",
                "FilterPolicyScope": "MessageAttributes",  # test if it also matches default values
            }
        )

        snapshot.match("subscribe-idempotent", subscribe_resp)

        # no attributes and empty attributes are working as well
        subscribe_resp = subscribe_queue_to_topic()
        snapshot.match("subscribe-idempotent-no-attributes", subscribe_resp)

        subscribe_resp = subscribe_queue_to_topic({})
        snapshot.match("subscribe-idempotent-empty-attributes", subscribe_resp)

        subscribe_resp = subscribe_queue_to_topic({"FilterPolicyScope": "MessageAttributes"})
        snapshot.match("subscribe-missing-attributes", subscribe_resp)

        with pytest.raises(ClientError) as e:
            subscribe_queue_to_topic(
                {
                    "RawMessageDelivery": "false",
                    "FilterPolicyScope": "MessageBody",
                }
            )
        snapshot.match("subscribe-diff-attributes", e.value.response)

    @markers.aws.validated
    def test_unsubscribe_idempotency(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        sub_arn = subscription["SubscriptionArn"]

        unsubscribe_1 = aws_client.sns.unsubscribe(SubscriptionArn=sub_arn)
        snapshot.match("unsubscribe-1", unsubscribe_1)
        unsubscribe_2 = aws_client.sns.unsubscribe(SubscriptionArn=sub_arn)
        snapshot.match("unsubscribe-2", unsubscribe_2)

    @markers.aws.validated
    def test_unsubscribe_wrong_arn_format(self, snapshot, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.sns.unsubscribe(SubscriptionArn="randomstring")

        snapshot.match("invalid-unsubscribe-arn-1", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.unsubscribe(SubscriptionArn="arn:aws:sns:us-east-1:random")

        snapshot.match("invalid-unsubscribe-arn-2", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.unsubscribe(SubscriptionArn="arn:aws:sns:us-east-1:111111111111:random")

        snapshot.match("invalid-unsubscribe-arn-3", e.value.response)


class TestSNSSubscriptionLambda:
    @markers.aws.validated
    def test_python_lambda_subscribe_sns_topic(
        self,
        sns_create_topic,
        sns_subscription,
        lambda_su_role,
        create_lambda_function,
        snapshot,
        aws_client,
    ):
        function_name = f"lambda-function-{short_uid()}"
        permission_id = f"test-statement-{short_uid()}"
        subject = "[Subject] Test subject"
        message = "Hello world."
        topic_arn = sns_create_topic()["TopicArn"]

        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )

        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=lambda_arn,
        )

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        aws_client.sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)

        # access events sent by lambda
        events = retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter="Records.*Sns",
            logs_client=aws_client.logs,
        )
        notification = events[0]["Records"][0]["Sns"]
        snapshot.match("notification", notification)

    @markers.aws.validated
    def test_sns_topic_as_lambda_dead_letter_queue(
        self,
        lambda_su_role,
        create_lambda_function,
        sns_create_topic,
        sqs_create_queue,
        sns_subscription,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        """Tests an async event chain: SNS => Lambda => SNS DLQ => SQS
        1) SNS => Lambda: An SNS subscription triggers the Lambda function asynchronously.
        2) Lambda => SNS DLQ: A failing Lambda function triggers the SNS DLQ after all retries are exhausted.
        3) SNS DLQ => SQS: An SNS subscription forwards the DLQ message to SQS.
        """
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$..Messages..MessageAttributes.RequestID.Value", "request-id"
            )
        )

        # create an SNS topic that will be used as a DLQ by the lambda
        dlq_topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        # sqs_subscription
        sns_create_sqs_subscription(topic_arn=dlq_topic_arn, queue_url=queue_url)

        # create an SNS topic that will be used to invoke the lambda
        lambda_topic_arn = sns_create_topic()["TopicArn"]

        function_name = f"lambda-function-{short_uid()}"
        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
            DeadLetterConfig={"TargetArn": dlq_topic_arn},
        )
        snapshot.match(
            "lambda-response-dlq-config",
            lambda_creation_response["CreateFunctionResponse"]["DeadLetterConfig"],
        )
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]

        # allow the SNS topic to invoke the lambda
        permission_id = f"test-statement-{short_uid()}"
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=lambda_topic_arn,
        )

        # subscribe the lambda to the SNS topic: lambda_subscription
        sns_subscription(
            TopicArn=lambda_topic_arn,
            Protocol="lambda",
            Endpoint=lambda_arn,
        )

        # Set retries to zero to speed up the test
        aws_client.lambda_.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=0,
        )

        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }
        aws_client.sns.publish(TopicArn=lambda_topic_arn, Message=json.dumps(payload))

        def receive_dlq():
            result = aws_client.sqs.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"], VisibilityTimeout=0
            )
            assert len(result["Messages"]) > 0
            return result

        sleep = 3 if is_aws_cloud() else 1
        messages = retry(receive_dlq, retries=30, sleep=sleep)

        messages["Messages"][0]["Body"] = json.loads(messages["Messages"][0]["Body"])
        messages["Messages"][0]["Body"]["Message"] = json.loads(
            messages["Messages"][0]["Body"]["Message"]
        )

        snapshot.match("messages", messages)

    @markers.aws.validated
    def test_redrive_policy_lambda_subscription(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        create_lambda_function,
        lambda_su_role,
        sns_subscription,
        sns_allow_topic_sqs_queue,
        snapshot,
        aws_client,
    ):
        dlq_url = sqs_create_queue()
        dlq_arn = sqs_get_queue_arn(dlq_url)
        topic_arn = sns_create_topic()["TopicArn"]
        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url, sqs_queue_arn=dlq_arn, sns_topic_arn=topic_arn
        )

        lambda_name = f"test-{short_uid()}"
        lambda_arn = create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )["CreateFunctionResponse"]["FunctionArn"]

        subscription = sns_subscription(TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )
        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"]
        )

        snapshot.match("subscription-attributes", response_attributes)

        aws_client.lambda_.delete_function(FunctionName=lambda_name)

        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test_redrive_policy",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "1"}},
        )

        response = aws_client.sqs.receive_message(
            QueueUrl=dlq_url, WaitTimeSeconds=10, MessageAttributeNames=["All"]
        )
        snapshot.match("messages", response)

    @markers.aws.validated
    @pytest.mark.parametrize("signature_version", ["1", "2"])
    def test_publish_lambda_verify_signature(
        self,
        aws_client,
        sns_create_topic,
        create_lambda_function,
        sns_subscription,
        lambda_su_role,
        snapshot,
        signature_version,
    ):
        # Lambda always returns SignatureVersion=1 in messages, however, it can be v2 and the signature needs to be
        # verified against v2 (SHA256). Weird bug on AWS side, we will do the same for now.

        function_name = f"lambda-function-{short_uid()}"
        permission_id = f"test-statement-{short_uid()}"
        subject = f"[Subject] Test subject Signature v{signature_version}"
        message = "Hello world."
        topic_arn = sns_create_topic(
            Attributes={
                "DisplayName": "TestTopicSignatureLambda",
                "SignatureVersion": signature_version,
            },
        )["TopicArn"]

        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )

        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=lambda_arn,
        )

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        aws_client.sns.publish(TopicArn=topic_arn, Subject=subject, Message=message)

        # access events sent by lambda
        events = retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter="Records.*Sns",
            logs_client=aws_client.logs,
        )

        message = events[0]["Records"][0]["Sns"]
        snapshot.match("notification", message)

        cert_url = message["SigningCertUrl"]
        get_cert_req = requests.get(cert_url)
        assert get_cert_req.ok

        cert = x509.load_pem_x509_certificate(get_cert_req.content)
        message_signature = message["Signature"]
        # create the canonical string
        fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
        # Build the string to be signed.
        string_to_sign = "".join(
            [f"{field}\n{message[field]}\n" for field in fields if field in message]
        )

        # decode the signature from base64.
        decoded_signature = base64.b64decode(message_signature)

        message_sig_version = message["SignatureVersion"]
        # this is a bug on AWS side, assert our behaviour is the same for now, this might get fixed
        assert message_sig_version == "1"
        signature_hash = hashes.SHA1() if signature_version == "1" else hashes.SHA256()

        # calculate signature value with cert
        is_valid = cert.public_key().verify(
            decoded_signature,
            to_bytes(string_to_sign),
            padding=padding.PKCS1v15(),
            algorithm=signature_hash,
        )
        # if the verification failed, it would raise `InvalidSignature`
        assert is_valid is None


class TestSNSSubscriptionSQS:
    @markers.aws.validated
    def test_subscribe_sqs_queue(
        self, sqs_create_queue, sns_create_topic, sns_create_sqs_subscription, snapshot, aws_client
    ):
        # TODO: check with non default external port

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        # create subscription with filter policy
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
        )
        snapshot.match("subscription-attributes", response_attributes)

        # publish message that satisfies the filter policy
        message = "This is a test message"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )

        # assert that message is received
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            VisibilityTimeout=0,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=4,
        )
        snapshot.match("messages", response)

    @markers.aws.validated
    def test_publish_unicode_chars(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        # publish message to SNS, receive it from SQS, assert that messages are equal
        message = 'ö§a1"_!?,. £$-'
        aws_client.sns.publish(TopicArn=topic_arn, Message=message)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )

        snapshot.match("received-message", response)

    @markers.aws.validated
    def test_attribute_raw_subscribe(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        # the hash isn't the same because of the Binary attributes (maybe decoding order?)
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfMessageAttributes",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            )
        )
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(
            topic_arn=topic_arn, queue_url=queue_url, Attributes={"RawMessageDelivery": "true"}
        )
        subscription_arn = subscription["SubscriptionArn"]

        response_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes", response_attributes)

        # publish message to SNS, receive it from SQS, assert that messages are equal and that they are Raw
        message = "This is a test message"
        binary_attribute = b"\x02\x03\x04"
        # extending this test case to test support for binary message attribute data
        # https://github.com/localstack/localstack/issues/2432
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"store": {"DataType": "Binary", "BinaryValue": binary_attribute}},
        )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        snapshot.match("messages-response", response)

    @markers.aws.validated
    def test_sqs_topic_subscription_confirmation(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription_attrs = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        def check_subscription():
            nonlocal subscription_attrs
            if not subscription_attrs["PendingConfirmation"] == "false":
                subscription_arn = subscription_attrs["SubscriptionArn"]
                subscription_attrs = aws_client.sns.get_subscription_attributes(
                    SubscriptionArn=subscription_arn
                )["Attributes"]
            else:
                snapshot.match("subscription-attrs", subscription_attrs)

            return subscription_attrs["PendingConfirmation"] == "false"

        # SQS subscriptions are auto confirmed if the endpoint and the topic are in the same AWS account
        assert poll_condition(check_subscription, timeout=5)

    @markers.aws.validated
    def test_publish_sqs_from_sns(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        response = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)

        string_value = "99.12"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": string_value}},
        )

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        snapshot.match("message-raw-true", response)
        # format is of SQS MessageAttributes when RawDelivery is set to "true"
        assert response["Messages"][0]["MessageAttributes"] == {
            "attr1": {"DataType": "Number", "StringValue": string_value}
        }

        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="false",
        )
        response = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-false", response)

        string_value = "100.12"
        aws_client.sns.publish(
            TargetArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": string_value}},
        )
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        snapshot.match("message-raw-false", response)
        message_body = json.loads(response["Messages"][0]["Body"])
        # format is SNS MessageAttributes when RawDelivery is "false"
        assert message_body["MessageAttributes"] == {
            "attr1": {"Type": "Number", "Value": string_value}
        }

    @markers.aws.validated
    def test_publish_batch_messages_from_sns_to_sqs(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        response = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)

        publish_batch_response = aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
                {
                    "Id": "1",
                    "Message": "Test Message with two attributes",
                    "Subject": "Subject",
                    "MessageAttributes": {
                        "attr1": {"DataType": "Number", "StringValue": "99.12"},
                        "attr2": {"DataType": "Number", "StringValue": "109.12"},
                    },
                },
                {
                    "Id": "2",
                    "Message": "Test Message with one attribute",
                    "Subject": "Subject",
                    "MessageAttributes": {"attr1": {"DataType": "Number", "StringValue": "19.12"}},
                },
                {
                    "Id": "3",
                    "Message": "Test Message without attribute",
                    "Subject": "Subject",
                },
                {
                    "Id": "4",
                    "Message": "Test Message without subject",
                },
                {
                    "Id": "5",
                    "Message": json.dumps({"default": "test default", "sqs": "test sqs"}),
                    "MessageStructure": "json",
                },
            ],
        )
        snapshot.match("publish-batch", publish_batch_response)

        messages = []

        def get_messages():
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                WaitTimeSeconds=1,
                VisibilityTimeout=0,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
            )
            for message in sqs_response["Messages"]:
                messages.append(message)
                aws_client.sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

            assert len(messages) == 5

        retry(get_messages, retries=10, sleep=0.1)
        # we need to sort the list (the order does not matter as we're not using FIFO)
        messages.sort(key=itemgetter("Body"))
        snapshot.match("messages", {"Messages": messages})

    @markers.aws.validated
    def test_publish_batch_messages_without_topic(self, sns_create_topic, snapshot, aws_client):
        topic_arn = sns_create_topic()["TopicArn"]
        fake_topic_arn = topic_arn + "fake-topic"

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=fake_topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": "Test Message with two attributes",
                        "Subject": "Subject",
                    }
                ],
            )
        snapshot.match("publish-batch-no-topic", e.value.response)

    @markers.aws.validated
    def test_publish_batch_exceptions(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        fifo_topic_name = f"topic-{short_uid()}.fifo"
        topic_arn = sns_create_topic(Name=fifo_topic_name, Attributes={"FifoTopic": "true"})[
            "TopicArn"
        ]

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": "Test message without Group ID",
                    }
                ],
            )
        snapshot.match("no-group-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": f"Id_{i}", "Message": "Too many messages"} for i in range(11)
                ],
            )
        snapshot.match("too-many-msg", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": "1", "Message": "Messages with the same ID"} for _ in range(2)
                ],
            )
        snapshot.match("same-msg-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": "Test message without MessageDeduplicationId",
                        "MessageGroupId": "msg1",
                    }
                ],
            )
        snapshot.match("no-dedup-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": json.dumps({"sqs": "test sqs"}),
                        "MessageStructure": "json",
                    }
                ],
            )
        snapshot.match("no-default-key-json", e.value.response)

    @markers.aws.validated
    def test_subscribe_to_sqs_with_queue_url(
        self, sns_create_topic, sqs_create_queue, sns_subscription, snapshot
    ):
        topic = sns_create_topic()
        topic_arn = topic["TopicArn"]
        queue_url = sqs_create_queue()
        with pytest.raises(ClientError) as e:
            sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_url)
        snapshot.match("sub-queue-url", e.value.response)

    @markers.aws.validated
    def test_publish_sqs_from_sns_with_xray_propagation(
        self, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot, aws_client
    ):
        def add_xray_header(request, **_kwargs):
            request.headers["X-Amzn-Trace-Id"] = (
                "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
            )

        try:
            aws_client.sns.meta.events.register("before-send.sns.Publish", add_xray_header)

            topic = sns_create_topic()
            topic_arn = topic["TopicArn"]
            queue_url = sqs_create_queue()
            sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
            aws_client.sns.publish(TargetArn=topic_arn, Message="X-Ray propagation test msg")

            response = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                AttributeNames=["SentTimestamp", "AWSTraceHeader"],
                MaxNumberOfMessages=1,
                MessageAttributeNames=["All"],
                VisibilityTimeout=2,
                WaitTimeSeconds=2,
            )

            assert len(response["Messages"]) == 1
            message = response["Messages"][0]
            snapshot.match("xray-msg", message)
            assert (
                message["Attributes"]["AWSTraceHeader"]
                == "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
            )
        finally:
            aws_client.sns.meta.events.unregister("before-send.sns.Publish", add_xray_header)

    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    @markers.aws.validated
    def test_redrive_policy_sqs_queue_subscription(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sqs_queue_exists,
        sns_create_sqs_subscription,
        sns_allow_topic_sqs_queue,
        raw_message_delivery,
        snapshot,
        aws_client,
    ):
        # the hash isn't the same because of the Binary attributes (maybe decoding order?)
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfMessageAttributes",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            )
        )
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        dlq_url = sqs_create_queue()
        dlq_arn = sqs_get_queue_arn(dlq_url)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )

        if raw_message_delivery:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"],
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url,
            sqs_queue_arn=dlq_arn,
            sns_topic_arn=topic_arn,
        )

        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        # AWS takes some time to delete the queue, which make the test fails as it delivers the message correctly
        assert poll_condition(lambda: not sqs_queue_exists(queue_url), timeout=5)

        message = "test_dlq_after_sqs_endpoint_deleted"
        message_attr = {
            "attr1": {
                "DataType": "Number",
                "StringValue": "111",
            },
            "attr2": {
                "DataType": "Binary",
                "BinaryValue": b"\x02\x03\x04",
            },
        }
        aws_client.sns.publish(TopicArn=topic_arn, Message=message, MessageAttributes=message_attr)

        response = aws_client.sqs.receive_message(
            QueueUrl=dlq_url,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        )
        snapshot.match("messages", response)

    @markers.aws.validated
    def test_message_attributes_not_missing(
        self, sns_create_sqs_subscription, sns_create_topic, sqs_create_queue, snapshot, aws_client
    ):
        # the hash isn't the same because of the Binary attributes (maybe decoding order?)
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfMessageAttributes",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            )
        )
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        attributes = {
            "an-attribute-key": {"DataType": "String", "StringValue": "an-attribute-value"},
            "binary-attribute": {"DataType": "Binary", "BinaryValue": b"\x02\x03\x04"},
        }

        publish_response = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="text",
            MessageAttributes=attributes,
        )
        snapshot.match("publish-msg-raw", publish_response)

        msg = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        # as SNS piggybacks on SQS MessageAttributes when RawDelivery is true
        # BinaryValue depends on SQS implementation, and is decoded automatically
        snapshot.match("raw-delivery-msg-attrs", msg)

        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=msg["Messages"][0]["ReceiptHandle"]
        )

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RawMessageDelivery",
            AttributeValue="false",
        )

        publish_response = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="text",
            MessageAttributes=attributes,
        )
        snapshot.match("publish-msg-json", publish_response)

        msg = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        snapshot.match("json-delivery-msg-attrs", msg)
        # binary payload in base64 encoded by AWS, UTF-8 for JSON
        # https://docs.aws.amazon.com/sns/latest/api/API_MessageAttributeValue.html

    @markers.aws.validated
    def test_subscription_after_failure_to_deliver(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sqs_queue_exists,
        sns_create_sqs_subscription,
        sns_allow_topic_sqs_queue,
        sqs_receive_num_messages,
        snapshot,
        aws_client,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        dlq_url = sqs_create_queue()
        dlq_arn = sqs_get_queue_arn(dlq_url)

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url,
            sqs_queue_arn=dlq_arn,
            sns_topic_arn=topic_arn,
        )

        sub_attrs = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("subscriptions-attrs", sub_attrs)

        message = "test_dlq_before_sqs_endpoint_deleted"
        aws_client.sns.publish(TopicArn=topic_arn, Message=message)
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=10, MaxNumberOfMessages=4
        )
        snapshot.match("messages-before-delete", response)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )

        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        # setting up a second queue to be able to poll and know approximately when the message on the deleted queue
        # have been published
        queue_test_url = sqs_create_queue()
        test_subscription = sns_create_sqs_subscription(
            topic_arn=topic_arn, queue_url=queue_test_url
        )
        test_subscription_arn = test_subscription["SubscriptionArn"]
        # try to send a message before setting a DLQ
        message = "test_dlq_after_sqs_endpoint_deleted"
        aws_client.sns.publish(TopicArn=topic_arn, Message=message)

        # to avoid race condition, publish is async and the redrive policy can be in effect before the actual publish
        # we wait until the 2nd subscription received the message
        poll_condition(
            lambda: sqs_receive_num_messages(
                queue_url=queue_test_url, expected_messages=1, max_iterations=2
            ),
            timeout=10,
        )
        aws_client.sns.unsubscribe(SubscriptionArn=test_subscription_arn)
        # we still wait a bit to be sure the message is well published
        time.sleep(1)

        # check the subscription is still there after we deleted the queue
        subscriptions = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
        snapshot.match("subscriptions", subscriptions)

        # set the RedrivePolicy with a DLQ. Subsequent failing messages to the subscription should go there
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )

        sub_attrs = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("subscriptions-attrs-with-redrive", sub_attrs)

        # AWS takes some time to delete the queue, which make the test fails as it delivers the message correctly
        assert poll_condition(lambda: not sqs_queue_exists(queue_url), timeout=5)

        # test sending and receiving multiple messages
        for i in range(2):
            message = f"test_dlq_after_sqs_endpoint_deleted_{i}"

            aws_client.sns.publish(TopicArn=topic_arn, Message=message)
            response = aws_client.sqs.receive_message(
                QueueUrl=dlq_url, WaitTimeSeconds=10, MaxNumberOfMessages=4
            )
            aws_client.sqs.delete_message(
                QueueUrl=dlq_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
            )

            snapshot.match(f"message-{i}-after-delete", response)

    @markers.aws.validated
    def test_empty_or_wrong_message_attributes(
        self, sns_create_sqs_subscription, sns_create_topic, sqs_create_queue, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        wrong_message_attributes = {
            "missing_string_attr": {"attr1": {"DataType": "String", "StringValue": ""}},
            "missing_binary_attr": {"attr1": {"DataType": "Binary", "BinaryValue": b""}},
            "str_attr_binary_value": {"attr1": {"DataType": "String", "BinaryValue": b"123"}},
            "int_attr_binary_value": {"attr1": {"DataType": "Number", "BinaryValue": b"123"}},
            "binary_attr_string_value": {"attr1": {"DataType": "Binary", "StringValue": "123"}},
            "invalid_attr_string_value": {
                "attr1": {"DataType": "InvalidType", "StringValue": "123"}
            },
            "too_long_name": {"a" * 257: {"DataType": "String", "StringValue": "123"}},
            "invalid_name": {"a^*?": {"DataType": "String", "StringValue": "123"}},
            "invalid_name_2": {".abc": {"DataType": "String", "StringValue": "123"}},
            "invalid_name_3": {"abc.": {"DataType": "String", "StringValue": "123"}},
            "invalid_name_4": {"a..bc": {"DataType": "String", "StringValue": "123"}},
        }

        for error_type, msg_attrs in wrong_message_attributes.items():
            with pytest.raises(ClientError) as e:
                aws_client.sns.publish(
                    TopicArn=topic_arn,
                    Message="test message",
                    MessageAttributes=msg_attrs,
                )

            snapshot.match(error_type, e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": "test-batch",
                        "MessageAttributes": wrong_message_attributes["missing_string_attr"],
                    },
                    {
                        "Id": "2",
                        "Message": "test-batch",
                        "MessageAttributes": wrong_message_attributes["str_attr_binary_value"],
                    },
                    {
                        "Id": "3",
                        "Message": "valid-batch",
                    },
                ],
            )
        snapshot.match("batch-exception", e.value.response)

    @markers.aws.validated
    def test_message_attributes_prefixes(
        self, sns_create_sqs_subscription, sns_create_topic, sqs_create_queue, snapshot, aws_client
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message="test message",
                MessageAttributes={"attr1": {"DataType": "String.", "StringValue": "prefixed-1"}},
            )
        snapshot.match("publish-error", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(
                TopicArn=topic_arn,
                Message="test message",
                MessageAttributes={
                    "attr1": {"DataType": "Stringprefixed", "StringValue": "prefixed-1"}
                },
            )
        snapshot.match("publish-error-2", e.value.response)

        response = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test message",
            MessageAttributes={
                "attr1": {"DataType": "String.prefixed", "StringValue": "prefixed-1"}
            },
        )
        snapshot.match("publish-ok-1", response)

        response = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test message",
            MessageAttributes={
                "attr1": {"DataType": "String.  prefixed.", "StringValue": "prefixed-1"}
            },
        )
        snapshot.match("publish-ok-2", response)

    @markers.aws.validated
    def test_message_structure_json_to_sqs(
        self, aws_client, sns_create_topic, sqs_create_queue, snapshot, sns_create_sqs_subscription
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_name = f"test-queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message = json.dumps({"default": "default field", "sqs": json.dumps({"field": "value"})})
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageStructure="json",
        )
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=10, MaxNumberOfMessages=1
        )
        snapshot.match("get-msg-json-sqs", response)
        receipt_handle = response["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # don't json dumps the SQS field, it will be ignored, and the message received will be the `default`
        message = json.dumps({"default": "default field", "sqs": {"field": "value"}})
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageStructure="json",
        )
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, WaitTimeSeconds=10, MaxNumberOfMessages=1
        )
        snapshot.match("get-msg-json-default", response)

    @markers.aws.validated
    @pytest.mark.parametrize("signature_version", ["1", "2"])
    def test_publish_sqs_verify_signature(
        self,
        aws_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        signature_version,
    ):
        topic_arn = sns_create_topic(
            Attributes={
                "DisplayName": "TestTopicSignature",
                "SignatureVersion": signature_version,
            },
        )["TopicArn"]

        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test signature value with attributes",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "1"}},
        )
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        )
        snapshot.match("messages", response)
        message = json.loads(response["Messages"][0]["Body"])

        cert_url = message["SigningCertURL"]
        get_cert_req = requests.get(cert_url)
        assert get_cert_req.ok

        cert = x509.load_pem_x509_certificate(get_cert_req.content)
        message_signature = message["Signature"]
        # create the canonical string
        fields = ["Message", "MessageId", "Subject", "Timestamp", "TopicArn", "Type"]
        # Build the string to be signed.
        string_to_sign = "".join(
            [f"{field}\n{message[field]}\n" for field in fields if field in message]
        )

        # decode the signature from base64.
        decoded_signature = base64.b64decode(message_signature)

        message_sig_version = message["SignatureVersion"]
        assert message_sig_version == signature_version
        signature_hash = hashes.SHA1() if message_sig_version == "1" else hashes.SHA256()

        # calculate signature value with cert
        is_valid = cert.public_key().verify(
            decoded_signature,
            to_bytes(string_to_sign),
            padding=padding.PKCS1v15(),
            algorithm=signature_hash,
        )
        # if the verification failed, it would raise `InvalidSignature`
        assert is_valid is None


class TestSNSSubscriptionSQSFifo:
    @markers.aws.validated
    @pytest.mark.parametrize("content_based_deduplication", [True, False])
    def test_message_to_fifo_sqs(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        content_based_deduplication,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"
        topic_attributes = {"FifoTopic": "true"}
        queue_attributes = {"FifoQueue": "true"}
        if content_based_deduplication:
            topic_attributes["ContentBasedDeduplication"] = "true"
            queue_attributes["ContentBasedDeduplication"] = "true"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes=queue_attributes,
        )

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message = "Test"
        kwargs = {"MessageGroupId": "message-group-id-1"}
        if not content_based_deduplication:
            kwargs["MessageDeduplicationId"] = "message-deduplication-id-1"

        aws_client.sns.publish(TopicArn=topic_arn, Message=message, **kwargs)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
        )
        snapshot.match("messages", response)

        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )
        # republish the message, to check deduplication
        aws_client.sns.publish(TopicArn=topic_arn, Message=message, **kwargs)
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=1,
            AttributeNames=["All"],
        )
        snapshot.match("dedup-messages", response)

    @markers.aws.validated
    @pytest.mark.parametrize("content_based_deduplication", [True, False])
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.dedup-messages.Messages"
        ],  # FIXME: introduce deduplication at Topic level, not only SQS
    )
    def test_fifo_topic_to_regular_sqs(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        content_based_deduplication,
        aws_client,
    ):
        # it seems change is coming on AWS, as FIFO topic do not require FIFO queues anymore. This might mean that
        # the FIFO logic is being migrated to SNS and do not rely on SQS FIFO anymore? or that the FIFO is only
        # guaranteed with FIFO queues, but you can also subscribe with regular subscribers for deduplication for ex. ?
        # The change in error message suggest the latter:
        # "RedrivePolicy: must use a FIFO queue as DLQ for a FIFO topic" became:
        # -> "RedrivePolicy: must use a FIFO queue as DLQ for a FIFO Subscription to a FIFO Topic."

        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}"
        topic_attributes = {"FifoTopic": "true"}
        if content_based_deduplication:
            topic_attributes["ContentBasedDeduplication"] = "true"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]
        queue_url = sqs_create_queue(QueueName=queue_name)

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message = "Test"
        kwargs = {"MessageGroupId": "message-group-id-1"}
        if not content_based_deduplication:
            kwargs["MessageDeduplicationId"] = "message-deduplication-id-1"

        aws_client.sns.publish(TopicArn=topic_arn, Message=message, **kwargs)

        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
        )
        snapshot.match("messages", response)

        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )
        # republish the message, to check deduplication
        # TODO: not implemented in LocalStack yet, only deduplication with FIFO SQS queues
        aws_client.sns.publish(TopicArn=topic_arn, Message=message, **kwargs)
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            WaitTimeSeconds=3,
            AttributeNames=["All"],
        )
        snapshot.match("dedup-messages", response)

    @markers.aws.validated
    def test_validations_for_fifo(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}"
        fifo_topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}"
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        not_fifo_dlq_name = f"queue-dlq-{short_uid()}"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        fifo_topic_arn = sns_create_topic(Name=fifo_topic_name, Attributes={"FifoTopic": "true"})[
            "TopicArn"
        ]

        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )

        queue_url = sqs_create_queue(QueueName=queue_name)
        not_fifo_dlq_url = sqs_create_queue(QueueName=not_fifo_dlq_name)

        with pytest.raises(ClientError) as e:
            sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=fifo_queue_url)

        assert e.match("standard SNS topic")
        snapshot.match("not-fifo-topic", e.value.response)

        # SNS does not reject a regular SQS queue subscribed to a FIFO topic anymore
        subscription_not_fifo = sns_create_sqs_subscription(
            topic_arn=fifo_topic_arn, queue_url=queue_url
        )
        snapshot.match("not-fifo-queue", subscription_not_fifo)

        not_fifo_queue_arn = sqs_get_queue_arn(not_fifo_dlq_url)
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_not_fifo["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": not_fifo_queue_arn}),
        )

        subscription = sns_create_sqs_subscription(
            topic_arn=fifo_topic_arn, queue_url=fifo_queue_url
        )
        queue_arn = sqs_get_queue_arn(queue_url)

        with pytest.raises(ClientError) as e:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"],
                AttributeName="RedrivePolicy",
                AttributeValue=json.dumps({"deadLetterTargetArn": queue_arn}),
            )
        snapshot.match("regular-queue-for-dlq-of-fifo-topic", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(TopicArn=fifo_topic_arn, Message="test")

        assert e.match("MessageGroupId")
        snapshot.match("no-msg-group-id", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(
                TopicArn=fifo_topic_arn, Message="test", MessageGroupId=short_uid()
            )
        # if ContentBasedDeduplication is not set at the topic level, it needs MessageDeduplicationId for each msg
        assert e.match("MessageDeduplicationId")
        assert e.match("ContentBasedDeduplication")
        snapshot.match("no-dedup-policy", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(
                TopicArn=topic_arn, Message="test", MessageDeduplicationId=short_uid()
            )
        assert e.match("MessageDeduplicationId")
        snapshot.match("no-msg-dedup-regular-topic", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(TopicArn=topic_arn, Message="test", MessageGroupId=short_uid())
        assert e.match("MessageGroupId")
        snapshot.match("no-msg-group-id-regular-topic", e.value.response)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.topic-attrs.Attributes.DeliveryPolicy",
            "$.topic-attrs.Attributes.EffectiveDeliveryPolicy",
            "$.topic-attrs.Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
        ]
    )
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_publish_fifo_messages_to_dlq(
        self,
        sns_create_topic,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_create_sqs_subscription,
        sns_allow_topic_sqs_queue,
        snapshot,
        raw_message_delivery,
        aws_client,
    ):
        # the hash isn't the same because of the Binary attributes (maybe decoding order?)
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MD5OfMessageAttributes",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            )
        )

        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"
        dlq_name = f"dlq-{short_uid()}.fifo"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes={"FifoTopic": "true"},
        )["TopicArn"]

        response = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic-attrs", response)

        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={"FifoQueue": "true"},
        )

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        if raw_message_delivery:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription_arn,
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        dlq_url = sqs_create_queue(
            QueueName=dlq_name,
            Attributes={"FifoQueue": "true"},
        )
        dlq_arn = sqs_get_queue_arn(dlq_url)

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url,
            sqs_queue_arn=dlq_arn,
            sns_topic_arn=topic_arn,
        )

        aws_client.sqs.delete_queue(QueueUrl=queue_url)

        message_group_id = "complexMessageGroupId"
        publish_batch_request_entries = [
            {
                "Id": "1",
                "MessageGroupId": message_group_id,
                "Message": "Test Message with two attributes",
                "Subject": "Subject",
                "MessageAttributes": {
                    "attr1": {"DataType": "Number", "StringValue": "99.12"},
                    "attr2": {"DataType": "Number", "StringValue": "109.12"},
                },
                "MessageDeduplicationId": "MessageDeduplicationId-1",
            },
            {
                "Id": "2",
                "MessageGroupId": message_group_id,
                "Message": "Test Message with one attribute",
                "Subject": "Subject",
                "MessageAttributes": {"attr1": {"DataType": "Number", "StringValue": "19.12"}},
                "MessageDeduplicationId": "MessageDeduplicationId-2",
            },
            {
                "Id": "3",
                "MessageGroupId": message_group_id,
                "Message": "Test Message without attribute",
                "Subject": "Subject",
                "MessageDeduplicationId": "MessageDeduplicationId-3",
            },
        ]

        publish_batch_response = aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=publish_batch_request_entries,
        )

        snapshot.match("publish-batch-response-fifo", publish_batch_response)

        assert "Successful" in publish_batch_response
        assert "Failed" in publish_batch_response

        for successful_resp in publish_batch_response["Successful"]:
            assert "Id" in successful_resp
            assert "MessageId" in successful_resp

        message_ids_received = set()
        messages = []

        def get_messages_from_dlq(amount_msg: int):
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            # MaxNumberOfMessages could return less than 3 messages
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=dlq_url,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
                MaxNumberOfMessages=10,
                WaitTimeSeconds=1,
                VisibilityTimeout=1,
            )

            for message in sqs_response["Messages"]:
                LOG.debug("Message received %s", message)
                if message["MessageId"] in message_ids_received:
                    continue

                message_ids_received.add(message["MessageId"])
                messages.append(message)
                aws_client.sqs.delete_message(
                    QueueUrl=dlq_url, ReceiptHandle=message["ReceiptHandle"]
                )

            assert len(messages) == amount_msg

        retry(get_messages_from_dlq, retries=5, sleep=1, amount_msg=3)
        snapshot.match("batch-messages-in-dlq", {"Messages": messages})
        messages.clear()

        publish_response = aws_client.sns.publish(
            TopicArn=topic_arn,
            Message="test-message",
            MessageGroupId="message-group-id-1",
            MessageDeduplicationId="message-deduplication-id-1",
        )
        snapshot.match("publish-response-fifo", publish_response)
        retry(get_messages_from_dlq, retries=5, sleep=1, amount_msg=1)
        snapshot.match("messages-in-dlq", {"Messages": messages})

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.topic-attrs.Attributes.DeliveryPolicy",
            "$.topic-attrs.Attributes.EffectiveDeliveryPolicy",
            "$.topic-attrs.Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
            "$.republish-batch-response-fifo.Successful..MessageId",  # TODO: SNS doesnt keep track of duplicate
            "$.republish-batch-response-fifo.Successful..SequenceNumber",  # TODO: SNS doesnt keep track of duplicate
        ]
    )
    @pytest.mark.parametrize("content_based_deduplication", [True, False])
    def test_publish_batch_messages_from_fifo_topic_to_fifo_queue(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        content_based_deduplication,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"
        topic_attributes = {"FifoTopic": "true"}
        queue_attributes = {"FifoQueue": "true"}
        if content_based_deduplication:
            topic_attributes["ContentBasedDeduplication"] = "true"
            queue_attributes["ContentBasedDeduplication"] = "true"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]

        response = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic-attrs", response)

        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes=queue_attributes,
        )

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )

        response = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)
        message_group_id = "complexMessageGroupId"
        publish_batch_request_entries = [
            {
                "Id": "1",
                "MessageGroupId": message_group_id,
                "Message": "Test Message with two attributes",
                "Subject": "Subject",
                "MessageAttributes": {
                    "attr1": {"DataType": "Number", "StringValue": "99.12"},
                    "attr2": {"DataType": "Number", "StringValue": "109.12"},
                },
            },
            {
                "Id": "2",
                "MessageGroupId": message_group_id,
                "Message": "Test Message with one attribute",
                "Subject": "Subject",
                "MessageAttributes": {"attr1": {"DataType": "Number", "StringValue": "19.12"}},
            },
            {
                "Id": "3",
                "MessageGroupId": message_group_id,
                "Message": "Test Message without attribute",
                "Subject": "Subject",
            },
        ]

        if not content_based_deduplication:
            for index, message in enumerate(publish_batch_request_entries):
                message["MessageDeduplicationId"] = f"MessageDeduplicationId-{index}"

        publish_batch_response = aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=publish_batch_request_entries,
        )

        snapshot.match("publish-batch-response-fifo", publish_batch_response)

        assert "Successful" in publish_batch_response
        assert "Failed" in publish_batch_response

        for successful_resp in publish_batch_response["Successful"]:
            assert "Id" in successful_resp
            assert "MessageId" in successful_resp

        message_ids_received = set()
        messages = []

        def get_messages():
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            # MaxNumberOfMessages could return less than 3 messages
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
                MaxNumberOfMessages=10,
                WaitTimeSeconds=1,
                VisibilityTimeout=10,
            )

            for _message in sqs_response["Messages"]:
                if _message["MessageId"] in message_ids_received:
                    continue

                message_ids_received.add(_message["MessageId"])
                messages.append(_message)
                aws_client.sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=_message["ReceiptHandle"]
                )

            assert len(messages) == 3

        retry(get_messages, retries=5, sleep=1)
        snapshot.match("messages", {"Messages": messages})

        publish_batch_response = aws_client.sns.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=publish_batch_request_entries,
        )

        snapshot.match("republish-batch-response-fifo", publish_batch_response)
        get_deduplicated_messages = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            AttributeNames=["All"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=3,
            VisibilityTimeout=0,
        )
        # there should not be any messages here, as they are duplicate
        # see https://docs.aws.amazon.com/sns/latest/dg/fifo-message-dedup.html
        snapshot.match("duplicate-messages", get_deduplicated_messages)

    @markers.aws.validated
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_publish_to_fifo_topic_to_sqs_queue_no_content_dedup(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        raw_message_delivery,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"
        topic_attributes = {"FifoTopic": "true", "ContentBasedDeduplication": "true"}
        queue_attributes = {"FifoQueue": "true"}

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes=queue_attributes,
        )

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        if raw_message_delivery:
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"],
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        # Topic has ContentBasedDeduplication set to true, the queue should receive only one message
        # SNS will create a MessageDeduplicationId for the SQS queue, as it does not have ContentBasedDeduplication
        for _ in range(2):
            aws_client.sns.publish(
                TopicArn=topic_arn, Message="Test single", MessageGroupId="message-group-id-1"
            )
            aws_client.sns.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "MessageGroupId": "message-group-id-1",
                        "Message": "Test batched",
                    }
                ],
            )

        messages = []
        message_ids_received = set()

        def get_messages():
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            # MaxNumberOfMessages could return less than 2 messages
            sqs_response = aws_client.sqs.receive_message(
                QueueUrl=queue_url,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
                MaxNumberOfMessages=10,
                WaitTimeSeconds=1,
                VisibilityTimeout=10,
            )

            for message in sqs_response["Messages"]:
                if message["MessageId"] in message_ids_received:
                    continue

                message_ids_received.add(message["MessageId"])
                messages.append(message)
                aws_client.sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

            assert len(messages) == 2

        retry(get_messages, retries=5, sleep=1)
        messages.sort(key=lambda x: x["Attributes"]["MessageDeduplicationId"])
        snapshot.match("messages", {"Messages": messages})

    @markers.aws.validated
    def test_publish_to_fifo_topic_deduplication_on_topic_level(
        self,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
        aws_client,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"
        topic_attributes = {"FifoTopic": "true", "ContentBasedDeduplication": "true"}
        queue_attributes = {"FifoQueue": "true"}

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes=queue_attributes,
        )

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        # TODO: for message deduplication, we are using the underlying features of the SQS queue
        # however, SQS queue only deduplicate at the Queue level, where the SNS topic deduplicate on the topic level
        # we will need to implement this
        # TODO: add a test with 2 subscriptions and a filter, to validate deduplication at topic level
        message = "Test"
        aws_client.sns.publish(
            TopicArn=topic_arn, Message=message, MessageGroupId="message-group-id-1"
        )
        time.sleep(
            0.5
        )  # this is to ensure order of arrival, because we do not deduplicate at SNS level yet
        aws_client.sns.publish(
            TopicArn=topic_arn, Message=message, MessageGroupId="message-group-id-2"
        )

        # get the deduplicated message and delete it
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            VisibilityTimeout=10,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
        )
        snapshot.match("messages", response)
        aws_client.sqs.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )
        # assert there are no more messages in the queue
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url,
            VisibilityTimeout=10,
            WaitTimeSeconds=1,
            AttributeNames=["All"],
        )
        snapshot.match("dedup-messages", response)

    @markers.aws.validated
    def test_publish_to_fifo_with_target_arn(self, sns_create_topic, aws_client):
        topic_name = f"topic-{short_uid()}.fifo"
        topic_attributes = {
            "FifoTopic": "true",
            "ContentBasedDeduplication": "true",
        }

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes=topic_attributes,
        )["TopicArn"]

        message = {"foo": "bar"}
        response = aws_client.sns.publish(
            TargetArn=topic_arn,
            Message=json.dumps({"default": json.dumps(message)}),
            MessageStructure="json",
            MessageGroupId="123",
        )
        assert "MessageId" in response


class TestSNSSubscriptionSES:
    @markers.aws.only_localstack
    def test_topic_email_subscription_confirmation(
        self, sns_create_topic, sns_subscription, aws_client
    ):
        # FIXME: we do not send the token to the email endpoint, so they cannot validate it
        # create AWS validated test for format
        # for now, access internals
        topic_arn = sns_create_topic()["TopicArn"]
        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint="localstack@yopmail.com",
        )
        subscription_arn = subscription["SubscriptionArn"]
        parsed_arn = parse_arn(subscription_arn)
        store = SnsProvider.get_store(parsed_arn["account"], parsed_arn["region"])

        sub_attr = aws_client.sns.get_subscription_attributes(SubscriptionArn=subscription_arn)
        assert sub_attr["Attributes"]["PendingConfirmation"] == "true"

        def check_subscription():
            for token, sub_arn in store.subscription_tokens.items():
                if sub_arn == subscription_arn:
                    aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token=token)

            sub_attributes = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert sub_attributes["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)


class TestSNSPlatformEndpoint:
    @markers.aws.only_localstack
    def test_subscribe_platform_endpoint(
        self,
        sns_create_topic,
        sns_subscription,
        sns_create_platform_application,
        aws_client,
        account_id,
        region_name,
    ):
        sns_backend = SnsProvider.get_store(account_id, region_name)
        topic_arn = sns_create_topic()["TopicArn"]

        app_arn = sns_create_platform_application(Name="app1", Platform="p1", Attributes={})[
            "PlatformApplicationArn"
        ]
        platform_arn = aws_client.sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token="token_1"
        )["EndpointArn"]

        # create subscription with filter policy
        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        sns_subscription(
            TopicArn=topic_arn,
            Protocol="application",
            Endpoint=platform_arn,
            Attributes={"FilterPolicy": json.dumps(filter_policy)},
        )
        # publish message that satisfies the filter policy
        message = "This is a test message"
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )

        # assert that message has been received
        def check_message():
            assert len(sns_backend.platform_endpoint_messages[platform_arn]) > 0

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    @markers.aws.needs_fixing
    @pytest.mark.skip(reason="Test asserts wrong behaviour")
    # AWS validating this is hard because we need real credentials for a GCM/Apple mobile app
    # TODO: AWS validate this test
    # See https://github.com/getmoto/moto/pull/6953 where Moto updated errors.
    def test_create_platform_endpoint_check_idempotency(
        self, sns_create_platform_application, aws_client
    ):
        response = sns_create_platform_application(
            Name=f"test-{short_uid()}",
            Platform="GCM",
            Attributes={"PlatformCredential": "123"},
        )
        token = "test1"
        # TODO: As per AWS docs:
        # > The CreatePlatformEndpoint action is idempotent, so if the requester already owns an endpoint
        # > with the same device token and attributes, that endpoint's ARN is returned without creating a new endpoint.
        # The 'Token' and 'Attributes' are critical to idempotent behaviour.
        kwargs_list = [
            {"Token": token, "CustomUserData": "test-data"},
            {"Token": token, "CustomUserData": "test-data"},
            {"Token": token},
            {"Token": token},
        ]
        platform_arn = response["PlatformApplicationArn"]
        responses = []
        for kwargs in kwargs_list:
            responses.append(
                aws_client.sns.create_platform_endpoint(
                    PlatformApplicationArn=platform_arn, **kwargs
                )
            )
        # Assert EndpointArn is returned in every call create platform call
        assert all("EndpointArn" in response for response in responses)
        endpoint_arn = responses[0]["EndpointArn"]

        with pytest.raises(ClientError) as e:
            aws_client.sns.create_platform_endpoint(
                PlatformApplicationArn=platform_arn,
                Token=token,
                CustomUserData="different-user-data",
            )
        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert (
            e.value.response["Error"]["Message"]
            == f"Endpoint {endpoint_arn} already exists with the same Token, but different attributes."
        )

    @markers.aws.needs_fixing
    # AWS validating this is hard because we need real credentials for a GCM/Apple mobile app
    def test_publish_disabled_endpoint(self, sns_create_platform_application, aws_client):
        response = sns_create_platform_application(
            Name=f"test-{short_uid()}",
            Platform="GCM",
            Attributes={"PlatformCredential": "123"},
        )
        platform_arn = response["PlatformApplicationArn"]
        response = aws_client.sns.create_platform_endpoint(
            PlatformApplicationArn=platform_arn,
            Token="test1",
        )
        endpoint_arn = response["EndpointArn"]

        get_attrs = aws_client.sns.get_endpoint_attributes(EndpointArn=endpoint_arn)
        assert get_attrs["Attributes"]["Enabled"] == "true"

        aws_client.sns.set_endpoint_attributes(
            EndpointArn=endpoint_arn, Attributes={"Enabled": "false"}
        )

        get_attrs = aws_client.sns.get_endpoint_attributes(EndpointArn=endpoint_arn)
        assert get_attrs["Attributes"]["Enabled"] == "false"

        with pytest.raises(ClientError) as e:
            message = {
                "GCM": '{ "notification": {"title": "Title of notification", "body": "It works" } }'
            }
            aws_client.sns.publish(
                TargetArn=endpoint_arn, MessageStructure="json", Message=json.dumps(message)
            )

        assert e.value.response["Error"]["Code"] == "EndpointDisabled"
        assert e.value.response["Error"]["Message"] == "Endpoint is disabled"

    @markers.aws.only_localstack  # needs real credentials for GCM/FCM
    @pytest.mark.skip(reason="Need to implement credentials validation when creating platform")
    def test_publish_to_gcm(self, sns_create_platform_application, aws_client):
        key = "mock_server_key"
        token = "mock_token"

        response = sns_create_platform_application(
            Name="firebase", Platform="GCM", Attributes={"PlatformCredential": key}
        )

        platform_app_arn = response["PlatformApplicationArn"]

        response = aws_client.sns.create_platform_endpoint(
            PlatformApplicationArn=platform_app_arn,
            Token=token,
        )
        endpoint_arn = response["EndpointArn"]

        message = {
            "GCM": '{ "notification": {"title": "Title of notification", "body": "It works" } }'
        }

        with pytest.raises(ClientError) as ex:
            aws_client.sns.publish(
                TargetArn=endpoint_arn, MessageStructure="json", Message=json.dumps(message)
            )
        assert ex.value.response["Error"]["Code"] == "InvalidParameter"

    @markers.aws.only_localstack
    def test_publish_to_platform_endpoint_is_dispatched(
        self,
        sns_create_topic,
        sns_subscription,
        sns_create_platform_application,
        aws_client,
        account_id,
        region_name,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        endpoints_arn = {}
        for platform_type in ["APNS", "GCM"]:
            application_platform_name = f"app-platform-{platform_type}-{short_uid()}"

            # Create an Apple platform application
            app_arn = sns_create_platform_application(
                Name=application_platform_name, Platform=platform_type, Attributes={}
            )["PlatformApplicationArn"]

            endpoint_arn = aws_client.sns.create_platform_endpoint(
                PlatformApplicationArn=app_arn, Token=short_uid()
            )["EndpointArn"]

            # store the endpoint for checking results
            endpoints_arn[platform_type] = endpoint_arn

            # subscribe this endpoint to a topic
            sns_subscription(
                TopicArn=topic_arn,
                Protocol="application",
                Endpoint=endpoint_arn,
            )

        # now we have two platform endpoints subscribed to the same topic
        message = {
            "default": "This is the default message which must be present when publishing a message to a topic.",
            "APNS": '{"aps":{"alert": "Check out these awesome deals!","url":"www.amazon.com"} }',
            "GCM": '{"data":{"message":"Check out these awesome deals!","url":"www.amazon.com"}}',
        }

        # publish to the topic
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps(message),
            MessageStructure="json",
        )

        sns_backend = SnsProvider.get_store(account_id, region_name)
        platform_endpoint_msgs = sns_backend.platform_endpoint_messages

        # assert that message has been received
        def check_message():
            assert len(platform_endpoint_msgs[endpoint_arn]) > 0

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # each endpoint should only receive the message that was directed to them
        assert platform_endpoint_msgs[endpoints_arn["GCM"]][0]["Message"] == message["GCM"]
        assert platform_endpoint_msgs[endpoints_arn["APNS"]][0]["Message"] == message["APNS"]


class TestSNSSMS:
    @markers.aws.only_localstack
    def test_publish_sms(self, aws_client, account_id, region_name):
        phone_number = "+33000000000"
        response = aws_client.sns.publish(PhoneNumber=phone_number, Message="This is a SMS")
        assert "MessageId" in response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        sns_backend = SnsProvider.get_store(
            account_id=account_id,
            region_name=region_name,
        )

        def check_messages():
            sms_was_found = False
            for message in sns_backend.sms_messages:
                if message["PhoneNumber"] == phone_number:
                    sms_was_found = True
                    break

            assert sms_was_found

        retry(check_messages, sleep=0.5)

    @markers.aws.validated
    def test_subscribe_sms_endpoint(self, sns_create_topic, sns_subscription, snapshot, aws_client):
        phone_number = "+123123123"
        topic_arn = sns_create_topic()["TopicArn"]
        response = sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=phone_number)
        snapshot.match("subscribe-sms-endpoint", response)

        sub_attrs = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=response["SubscriptionArn"]
        )
        snapshot.match("subscribe-sms-attrs", sub_attrs)

    @markers.aws.only_localstack
    def test_publish_sms_endpoint(
        self, sns_create_topic, sns_subscription, aws_client, account_id, region_name
    ):
        list_of_contacts = [
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
        ]
        message = "Good news everyone!"
        topic_arn = sns_create_topic()["TopicArn"]
        for number in list_of_contacts:
            sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=number)

        aws_client.sns.publish(Message=message, TopicArn=topic_arn)

        sns_backend = SnsProvider.get_store(account_id, region_name)

        def check_messages():
            sms_messages = sns_backend.sms_messages
            for contact in list_of_contacts:
                sms_was_found = False
                for _message in sms_messages:
                    if _message["PhoneNumber"] == contact:
                        sms_was_found = True
                        break

                assert sms_was_found

        retry(check_messages, sleep=0.5)

    @markers.aws.validated
    def test_publish_wrong_phone_format(
        self, sns_create_topic, sns_subscription, snapshot, aws_client
    ):
        message = "Good news everyone!"
        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message=message, PhoneNumber="+1a234")

        snapshot.match("invalid-number", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.sns.publish(Message=message, PhoneNumber="NAA+15551234567")

        snapshot.match("wrong-format", e.value.response)

        topic_arn = sns_create_topic()["TopicArn"]
        with pytest.raises(ClientError) as e:
            sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint="NAA+15551234567")
        snapshot.match("wrong-endpoint", e.value.response)


class TestSNSSubscriptionHttp:
    @markers.aws.validated
    def test_http_subscription_response(
        self,
        sns_create_topic,
        sns_subscription,
        aws_client,
        snapshot,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        snapshot.match("topic-arn", {"TopicArn": topic_arn})

        # we need to hit whatever URL, even external, the publishing is async, but we need an endpoint who won't
        # confirm the subscription
        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="http",
            Endpoint="http://example.com",
            ReturnSubscriptionArn=False,
        )
        snapshot.match("subscription", subscription)

        subscription_with_arn = sns_subscription(
            TopicArn=topic_arn,
            Protocol="http",
            Endpoint="http://example.com",
            ReturnSubscriptionArn=True,
        )
        snapshot.match("subscription-with-arn", subscription_with_arn)

    @markers.aws.manual_setup_required
    def test_redrive_policy_http_subscription(
        self, sns_create_topic, sqs_create_queue, sqs_get_queue_arn, sns_subscription, aws_client
    ):
        dlq_name = f"dlq-{short_uid()}"
        dlq_url = sqs_create_queue(QueueName=dlq_name)
        dlq_arn = sqs_get_queue_arn(dlq_url)
        topic_arn = sns_create_topic()["TopicArn"]

        # create HTTP endpoint and connect it to SNS topic
        with HTTPServer() as server:
            server.expect_request("/subscription").respond_with_data(b"", 200)
            http_endpoint = server.url_for("/subscription")
            wait_for_port_open(server.port)

            subscription = sns_subscription(
                TopicArn=topic_arn, Protocol="http", Endpoint=http_endpoint
            )
            aws_client.sns.set_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"],
                AttributeName="RedrivePolicy",
                AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
            )

            # wait for subscription notification to arrive at http endpoint
            poll_condition(lambda: len(server.log) >= 1, timeout=10)
            request, _ = server.log[0]
            event = request.get_json(force=True)
            assert request.path.endswith("/subscription")
            assert event["Type"] == "SubscriptionConfirmation"
            assert event["TopicArn"] == topic_arn
            aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token=event["Token"])

        wait_for_port_closed(server.port)

        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"message": "test_redrive_policy"}),
        )

        response = aws_client.sqs.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = json.loads(response["Messages"][0]["Body"])
        assert message["Type"] == "Notification"
        assert json.loads(message["Message"])["message"] == "test_redrive_policy"

    @markers.aws.manual_setup_required
    def test_multiple_subscriptions_http_endpoint(
        self, sns_create_topic, sns_subscription, aws_client
    ):
        # create a topic
        topic_arn = sns_create_topic()["TopicArn"]

        # build fake http server endpoints
        _requests = queue.Queue()

        # create HTTP endpoint and connect it to SNS topic
        def handler(_request):
            _requests.put(_request)
            return Response(status=429)

        number_of_endpoints = 4

        servers = []
        try:
            for _ in range(number_of_endpoints):
                server = HTTPServer()
                server.start()
                servers.append(server)
                server.expect_request("/").respond_with_handler(handler)
                http_endpoint = server.url_for("/")
                wait_for_port_open(http_endpoint)

                sns_subscription(TopicArn=topic_arn, Protocol="http", Endpoint=http_endpoint)

            # fetch subscription information
            subscription_list = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
            assert subscription_list["ResponseMetadata"]["HTTPStatusCode"] == 200
            assert (
                len(subscription_list["Subscriptions"]) == number_of_endpoints
            ), f"unexpected number of subscriptions {subscription_list}"

            tokens = []
            for _ in range(number_of_endpoints):
                request = _requests.get(timeout=2)
                request_data = request.get_json(True)
                tokens.append(request_data["Token"])
                assert request_data["TopicArn"] == topic_arn

            with pytest.raises(queue.Empty):
                # make sure only four requests are received
                _requests.get(timeout=1)

            # assert the first subscription is pending confirmation
            sub_1 = subscription_list["Subscriptions"][0]
            sub_1_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=sub_1["SubscriptionArn"]
            )
            assert sub_1_attrs["Attributes"]["PendingConfirmation"] == "true"

            # assert the second subscription is pending confirmation
            sub_2 = subscription_list["Subscriptions"][1]
            sub_2_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=sub_2["SubscriptionArn"]
            )
            assert sub_2_attrs["Attributes"]["PendingConfirmation"] == "true"

            # confirm the first subscription
            response = aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token=tokens[0])
            # assert the confirmed subscription is the first one
            assert response["SubscriptionArn"] == sub_1["SubscriptionArn"]

            # assert the first subscription is confirmed
            sub_1_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=sub_1["SubscriptionArn"]
            )
            assert sub_1_attrs["Attributes"]["PendingConfirmation"] == "false"

            # assert the second subscription is NOT confirmed
            sub_2_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=sub_2["SubscriptionArn"]
            )
            assert sub_2_attrs["Attributes"]["PendingConfirmation"] == "true"

        finally:
            subscription_list = aws_client.sns.list_subscriptions_by_topic(TopicArn=topic_arn)
            for subscription in subscription_list["Subscriptions"]:
                aws_client.sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
            for server in servers:
                server.stop()

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$.http-message-headers.Accept",  # requests adds the header but not SNS, not very important
            "$.http-message-headers-raw.Accept",
            "$.http-confirm-sub-headers.Accept",
        ]
    )
    def test_subscribe_external_http_endpoint(
        self, sns_create_http_endpoint, raw_message_delivery, aws_client, snapshot
    ):
        def _get_snapshot_requests_response(response: requests.Response) -> dict:
            parsed_xml_body = xmltodict.parse(response.content)
            for root_tag, fields in parsed_xml_body.items():
                fields.pop("@xmlns", None)
                if "ResponseMetadata" in fields:
                    fields["ResponseMetadata"]["HTTPHeaders"] = dict(response.headers)
                    fields["ResponseMetadata"]["HTTPStatusCode"] = response.status_code
            return parsed_xml_body

        def _clean_headers(response_headers: dict):
            return {key: val for key, val in response_headers.items() if "Forwarded" not in key}

        snapshot.add_transformer(
            [
                snapshot.transform.key_value("RequestId"),
                snapshot.transform.key_value("Token"),
                snapshot.transform.key_value("Host"),
                snapshot.transform.key_value(
                    "Content-Length", reference_replacement=False
                ),  # might change depending on compression
                snapshot.transform.key_value(
                    "Connection", reference_replacement=False
                ),  # casing might change
                snapshot.transform.regex(
                    r"(?i)(?<=SubscribeURL[\"|']:\s[\"|'])(https?.*?)(?=/\?Action=ConfirmSubscription)",
                    replacement="<subscribe-domain>",
                ),
            ]
        )

        # Necessitate manual set up to allow external access to endpoint, only in local testing
        topic_arn, subscription_arn, endpoint_url, server = sns_create_http_endpoint(
            raw_message_delivery
        )
        assert poll_condition(
            lambda: len(server.log) >= 1,
            timeout=5,
        )
        sub_request, _ = server.log[0]
        payload = sub_request.get_json(force=True)
        snapshot.match("subscription-confirmation", payload)
        assert payload["Type"] == "SubscriptionConfirmation"
        assert sub_request.headers["x-amz-sns-message-type"] == "SubscriptionConfirmation"
        assert "Signature" in payload
        assert "SigningCertURL" in payload

        snapshot.match("http-confirm-sub-headers", _clean_headers(sub_request.headers))

        token = payload["Token"]
        subscribe_url = payload["SubscribeURL"]
        service_url, subscribe_url_path = payload["SubscribeURL"].rsplit("/", maxsplit=1)
        assert subscribe_url == (
            f"{service_url}/?Action=ConfirmSubscription&TopicArn={topic_arn}&Token={token}"
        )

        test_broken_confirm_url = (
            f"{service_url}/?Action=ConfirmSubscription&TopicArn=not-an-arn&Token={token}"
        )
        broken_confirm_subscribe_request = requests.get(test_broken_confirm_url)
        snapshot.match(
            "broken-topic-arn-confirm",
            _get_snapshot_requests_response(broken_confirm_subscribe_request),
        )

        test_broken_token_confirm_url = (
            f"{service_url}/?Action=ConfirmSubscription&TopicArn={topic_arn}&Token=abc123"
        )
        broken_token_confirm_subscribe_request = requests.get(test_broken_token_confirm_url)
        snapshot.match(
            "broken-token-confirm",
            _get_snapshot_requests_response(broken_token_confirm_subscribe_request),
        )

        # using the right topic name with a different region will fail when confirming the subscription
        parsed_arn = parse_arn(topic_arn)
        different_region = "eu-central-1" if parsed_arn["region"] != "eu-central-1" else "us-east-1"
        different_region_topic = topic_arn.replace(parsed_arn["region"], different_region)
        different_region_topic_confirm_url = f"{service_url}/?Action=ConfirmSubscription&TopicArn={different_region_topic}&Token={token}"
        region_topic_confirm_subscribe_request = requests.get(different_region_topic_confirm_url)
        snapshot.match(
            "different-region-arn-confirm",
            _get_snapshot_requests_response(region_topic_confirm_subscribe_request),
        )

        # but a nonexistent topic in the right region will succeed
        last_fake_topic_char = "a" if topic_arn[-1] != "a" else "b"
        nonexistent = topic_arn[:-1] + last_fake_topic_char
        assert nonexistent != topic_arn
        test_wrong_topic_confirm_url = (
            f"{service_url}/?Action=ConfirmSubscription&TopicArn={nonexistent}&Token={token}"
        )
        wrong_topic_confirm_subscribe_request = requests.get(test_wrong_topic_confirm_url)
        snapshot.match(
            "nonexistent-token-confirm",
            _get_snapshot_requests_response(wrong_topic_confirm_subscribe_request),
        )

        # weirdly, even with a wrong topic, SNS will confirm the topic
        subscription_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        assert subscription_attributes["Attributes"]["PendingConfirmation"] == "false"

        confirm_subscribe_request = requests.get(subscribe_url)
        confirm_subscribe = xmltodict.parse(confirm_subscribe_request.content)
        assert (
            confirm_subscribe["ConfirmSubscriptionResponse"]["ConfirmSubscriptionResult"][
                "SubscriptionArn"
            ]
            == subscription_arn
        )
        # also confirm that ConfirmSubscription is idempotent
        snapshot.match(
            "confirm-subscribe", _get_snapshot_requests_response(confirm_subscribe_request)
        )

        subscription_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        assert subscription_attributes["Attributes"]["PendingConfirmation"] == "false"

        message = "test_external_http_endpoint"
        aws_client.sns.publish(TopicArn=topic_arn, Message=message)

        assert poll_condition(
            lambda: len(server.log) >= 2,
            timeout=5,
        )
        notification_request, _ = server.log[1]
        assert notification_request.headers["x-amz-sns-message-type"] == "Notification"

        expected_unsubscribe_url = (
            f"{service_url}/?Action=Unsubscribe&SubscriptionArn={subscription_arn}"
        )
        if raw_message_delivery:
            payload = notification_request.data.decode()
            assert payload == message
            snapshot.match("http-message-headers-raw", _clean_headers(notification_request.headers))
        else:
            payload = notification_request.get_json(force=True)
            assert payload["Type"] == "Notification"
            assert "Signature" in payload
            assert "SigningCertURL" in payload
            assert payload["Message"] == message
            assert payload["UnsubscribeURL"] == expected_unsubscribe_url
            snapshot.match("http-message", payload)
            snapshot.match("http-message-headers", _clean_headers(notification_request.headers))

        unsub_request = requests.get(expected_unsubscribe_url)
        unsubscribe_confirmation = xmltodict.parse(unsub_request.content)
        assert "UnsubscribeResponse" in unsubscribe_confirmation
        snapshot.match("unsubscribe-response", _get_snapshot_requests_response(unsub_request))

        assert poll_condition(
            lambda: len(server.log) >= 3,
            timeout=5,
        )
        unsub_request, _ = server.log[2]

        payload = unsub_request.get_json(force=True)
        assert payload["Type"] == "UnsubscribeConfirmation"
        assert unsub_request.headers["x-amz-sns-message-type"] == "UnsubscribeConfirmation"
        assert "Signature" in payload
        assert "SigningCertURL" in payload
        token = payload["Token"]
        assert payload["SubscribeURL"] == (
            f"{service_url}/?" f"Action=ConfirmSubscription&TopicArn={topic_arn}&Token={token}"
        )
        snapshot.match("unsubscribe-request", payload)

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_dlq_external_http_endpoint(
        self,
        sqs_create_queue,
        sqs_get_queue_arn,
        sns_create_http_endpoint,
        sns_allow_topic_sqs_queue,
        raw_message_delivery,
        aws_client,
    ):
        # Necessitate manual set up to allow external access to endpoint, only in local testing
        topic_arn, http_subscription_arn, endpoint_url, server = sns_create_http_endpoint(
            raw_message_delivery
        )

        dlq_url = sqs_create_queue()
        dlq_arn = sqs_get_queue_arn(dlq_url)

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url, sqs_queue_arn=dlq_arn, sns_topic_arn=topic_arn
        )
        aws_client.sns.set_subscription_attributes(
            SubscriptionArn=http_subscription_arn,
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )
        assert poll_condition(
            lambda: len(server.log) >= 1,
            timeout=5,
        )
        sub_request, _ = server.log[0]
        payload = sub_request.get_json(force=True)
        assert payload["Type"] == "SubscriptionConfirmation"
        assert sub_request.headers["x-amz-sns-message-type"] == "SubscriptionConfirmation"

        subscribe_url = payload["SubscribeURL"]
        service_url, subscribe_url_path = payload["SubscribeURL"].rsplit("/", maxsplit=1)

        confirm_subscribe_request = requests.get(subscribe_url)
        confirm_subscribe = xmltodict.parse(confirm_subscribe_request.content)
        assert (
            confirm_subscribe["ConfirmSubscriptionResponse"]["ConfirmSubscriptionResult"][
                "SubscriptionArn"
            ]
            == http_subscription_arn
        )

        subscription_attributes = aws_client.sns.get_subscription_attributes(
            SubscriptionArn=http_subscription_arn
        )
        assert subscription_attributes["Attributes"]["PendingConfirmation"] == "false"

        server.stop()
        wait_for_port_closed(server.port)

        message = "test_dlq_external_http_endpoint"
        aws_client.sns.publish(TopicArn=topic_arn, Message=message)

        response = aws_client.sqs.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=3)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"

        if raw_message_delivery:
            assert response["Messages"][0]["Body"] == message
        else:
            received_message = json.loads(response["Messages"][0]["Body"])
            assert received_message["Type"] == "Notification"
            assert received_message["Message"] == message

        receipt_handle = response["Messages"][0]["ReceiptHandle"]
        aws_client.sqs.delete_message(QueueUrl=dlq_url, ReceiptHandle=receipt_handle)

        expected_unsubscribe_url = (
            f"{service_url}/?Action=Unsubscribe&SubscriptionArn={http_subscription_arn}"
        )

        unsub_request = requests.get(expected_unsubscribe_url)
        unsubscribe_confirmation = xmltodict.parse(unsub_request.content)
        assert "UnsubscribeResponse" in unsubscribe_confirmation

        response = aws_client.sqs.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=2)
        # AWS doesn't send to the DLQ if the UnsubscribeConfirmation fails to be delivered
        assert "Messages" not in response or response["Messages"] == []


class TestSNSSubscriptionFirehose:
    @markers.aws.validated
    def test_publish_to_firehose_with_s3(
        self,
        create_role,
        s3_create_bucket,
        firehose_create_delivery_stream,
        sns_create_topic,
        sns_subscription,
        aws_client,
    ):
        role_name = f"test-role-{short_uid()}"
        stream_name = f"test-stream-{short_uid()}"
        bucket_name = f"test-bucket-{short_uid()}"
        topic_name = f"test_topic_{short_uid()}"

        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "s3.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "firehose.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }

        role = create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))

        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonKinesisFirehoseFullAccess",
        )

        aws_client.iam.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess"
        )
        subscription_role_arn = role["Role"]["Arn"]

        if is_aws_cloud():
            time.sleep(10)

        s3_create_bucket(Bucket=bucket_name)

        stream = firehose_create_delivery_stream(
            DeliveryStreamName=stream_name,
            DeliveryStreamType="DirectPut",
            S3DestinationConfiguration={
                "RoleARN": subscription_role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket_name}",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
            },
        )

        topic = sns_create_topic(Name=topic_name)
        sns_subscription(
            TopicArn=topic["TopicArn"],
            Protocol="firehose",
            Endpoint=stream["DeliveryStreamARN"],
            Attributes={"SubscriptionRoleArn": subscription_role_arn},
            ReturnSubscriptionArn=True,
        )

        message = json.dumps({"message": "hello world"})
        message_attributes = {
            "testAttribute": {"DataType": "String", "StringValue": "valueOfAttribute"}
        }
        aws_client.sns.publish(
            TopicArn=topic["TopicArn"], Message=message, MessageAttributes=message_attributes
        )

        def validate_content():
            files = aws_client.s3.list_objects(Bucket=bucket_name)["Contents"]
            f = BytesIO()
            aws_client.s3.download_fileobj(bucket_name, files[0]["Key"], f)
            content = to_str(f.getvalue())

            sns_message = json.loads(content.split("\n")[0])

            assert "Type" in sns_message
            assert "MessageId" in sns_message
            assert "Message" in sns_message
            assert "Timestamp" in sns_message

            assert message == sns_message["Message"]

        retries = 5
        sleep = 1
        sleep_before = 0
        if is_aws_cloud():
            retries = 30
            sleep = 10
            sleep_before = 10

        retry(validate_content, retries=retries, sleep_before=sleep_before, sleep=sleep)


class TestSNSMultiAccounts:
    @pytest.fixture
    def sns_primary_client(self, aws_client):
        return aws_client.sns

    @pytest.fixture
    def sns_secondary_client(self, secondary_aws_client):
        return secondary_aws_client.sns

    @pytest.fixture
    def sqs_primary_client(self, aws_client):
        return aws_client.sqs

    @pytest.fixture
    def sqs_secondary_client(self, secondary_aws_client):
        return secondary_aws_client.sqs

    @markers.aws.only_localstack
    def test_cross_account_access(self, sns_primary_client, sns_secondary_client):
        # Cross-account access is supported for below operations.
        # This list is taken from ActionName param of the AddPermissions operation
        #
        # - GetTopicAttributes
        # - SetTopicAttributes
        # - AddPermission
        # - RemovePermission
        # - Publish
        # - Subscribe
        # - ListSubscriptionsByTopic
        # - DeleteTopic

        topic_name = f"topic-{short_uid()}"
        topic_arn = sns_primary_client.create_topic(Name=topic_name)["TopicArn"]

        assert sns_secondary_client.set_topic_attributes(
            TopicArn=topic_arn, AttributeName="DisplayName", AttributeValue="xenon"
        )

        response = sns_secondary_client.get_topic_attributes(TopicArn=topic_arn)
        assert response["Attributes"]["DisplayName"] == "xenon"

        assert sns_secondary_client.add_permission(
            TopicArn=topic_arn,
            Label="foo",
            AWSAccountId=["666666666666"],
            ActionName=["AddPermission"],
        )
        assert sns_secondary_client.remove_permission(TopicArn=topic_arn, Label="foo")

        assert sns_secondary_client.publish(TopicArn=topic_arn, Message="hello world")

        subscription_arn = sns_secondary_client.subscribe(
            TopicArn=topic_arn, Protocol="email", Endpoint="devil@hell.com"
        )["SubscriptionArn"]

        response = sns_secondary_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        subscriptions = [s["SubscriptionArn"] for s in response["Subscriptions"]]
        assert subscription_arn in subscriptions

        response = sns_primary_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
        response = sns_primary_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        assert response["Attributes"]["RawMessageDelivery"] == "true"

        assert sns_secondary_client.delete_topic(TopicArn=topic_arn)

    @markers.aws.only_localstack
    def test_cross_account_publish_to_sqs(
        self,
        secondary_account_id,
        region_name,
        sns_primary_client,
        sns_secondary_client,
        sqs_primary_client,
        sqs_secondary_client,
        sqs_get_queue_arn,
    ):
        """
        This test validates that we can publish to SQS queues that are not in the default account, and that another
        account can publish to the topic as well

        Note: we are not setting Queue policies here as it's only in localstack and IAM is not enforced, for the sake
        of simplicity
        """

        topic_name = "sample_topic"
        topic_1 = sns_primary_client.create_topic(Name=topic_name)
        topic_1_arn = topic_1["TopicArn"]

        # create a queue with the primary AccountId
        queue_name = "sample_queue"
        queue_1 = sqs_primary_client.create_queue(QueueName=queue_name)
        queue_1_url = queue_1["QueueUrl"]
        queue_1_arn = sqs_get_queue_arn(queue_1_url)

        # create a queue with the secondary AccountId
        queue_2 = sqs_secondary_client.create_queue(QueueName=queue_name)
        queue_2_url = queue_2["QueueUrl"]
        # test that we get the right queue URL at the same time, even if we use the primary client
        queue_2_arn = sqs_queue_arn(
            queue_2_url,
            secondary_account_id,
            region_name,
        )

        # create a second queue with the secondary AccountId
        queue_name_2 = "sample_queue_two"
        queue_3 = sqs_secondary_client.create_queue(QueueName=queue_name_2)
        queue_3_url = queue_3["QueueUrl"]
        # test that we get the right queue URL at the same time, even if we use the primary client
        queue_3_arn = sqs_queue_arn(
            queue_3_url,
            secondary_account_id,
            region_name,
        )

        # test that we can subscribe with the primary client to a queue from the same account
        sns_primary_client.subscribe(
            TopicArn=topic_1_arn,
            Protocol="sqs",
            Endpoint=queue_1_arn,
        )

        # test that we can subscribe with the primary client to a queue from the secondary account
        sns_primary_client.subscribe(
            TopicArn=topic_1_arn,
            Protocol="sqs",
            Endpoint=queue_2_arn,
        )

        # test that we can subscribe with the secondary client (not owning the topic) to a queue of the secondary client
        sns_secondary_client.subscribe(
            TopicArn=topic_1_arn,
            Protocol="sqs",
            Endpoint=queue_3_arn,
        )

        # now, we have 3 subscriptions in topic_1, one to the queue_1 located in the same account, and 2 to queue_2 and
        # queue_3 located in the secondary account
        subscriptions = sns_primary_client.list_subscriptions_by_topic(TopicArn=topic_1_arn)
        assert len(subscriptions["Subscriptions"]) == 3

        sns_primary_client.publish(TopicArn=topic_1_arn, Message="TestMessageOwner")

        def get_messages_from_queues(message_content: str):
            for client, queue_url in (
                (sqs_primary_client, queue_1_url),
                (sqs_secondary_client, queue_2_url),
                (sqs_secondary_client, queue_3_url),
            ):
                response = client.receive_message(
                    QueueUrl=queue_url,
                    VisibilityTimeout=0,
                    WaitTimeSeconds=5,
                )
                messages = response["Messages"]
                assert len(messages) == 1
                assert topic_1_arn in messages[0]["Body"]
                assert message_content in messages[0]["Body"]
                client.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=messages[0]["ReceiptHandle"]
                )

        get_messages_from_queues("TestMessageOwner")

        # assert that we can also publish to the topic 1 from the secondary account
        sns_secondary_client.publish(TopicArn=topic_1_arn, Message="TestMessageSecondary")

        get_messages_from_queues("TestMessageSecondary")


class TestSNSPublishDelivery:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Attributes.DeliveryPolicy",
            "$..Attributes.EffectiveDeliveryPolicy",
            "$..Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
        ]
    )
    def test_delivery_lambda(
        self,
        sns_create_topic,
        sns_subscription,
        lambda_su_role,
        create_lambda_function,
        create_role,
        create_policy,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformers_list(
            [
                snapshot.transform.key_value(
                    "dwellTimeMs", reference_replacement=False, value_replacement="<time-ms>"
                ),
                snapshot.transform.key_value("nextBackwardToken"),
                snapshot.transform.key_value("nextForwardToken"),
            ]
        )
        function_name = f"lambda-function-{short_uid()}"
        permission_id = f"test-statement-{short_uid()}"
        subject = "[Subject] Test subject"
        message_fail = "Should not be received"
        message_success = "Should be received"
        topic_name = f"test-topic-{short_uid()}"
        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]
        parsed_arn = parse_arn(topic_arn)
        account_id = parsed_arn["account"]
        region = parsed_arn["region"]
        role_name = f"SNSSuccessFeedback-{short_uid()}"
        policy_name = f"SNSSuccessFeedback-policy-{short_uid()}"

        # enable Success Feedback from SNS to be sent to CloudWatch
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        cloudwatch_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:PutMetricFilter",
                        "logs:PutRetentionPolicy",
                    ],
                    "Resource": ["*"],
                }
            ],
        }

        role_response = create_role(
            RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
        )
        role_arn = role_response["Role"]["Arn"]
        policy_arn = create_policy(
            PolicyName=policy_name, PolicyDocument=json.dumps(cloudwatch_policy)
        )["Policy"]["Arn"]
        aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        if is_aws_cloud():
            # wait for the policy to be properly attached
            time.sleep(20)

        topic_attributes = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("get-topic-attrs", topic_attributes)

        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=Runtime.python3_12,
            role=lambda_su_role,
        )
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId=permission_id,
            Action="lambda:InvokeFunction",
            Principal="sns.amazonaws.com",
            SourceArn=topic_arn,
        )

        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="lambda",
            Endpoint=lambda_arn,
        )

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_attrs = aws_client.sns.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        publish_no_logs = aws_client.sns.publish(
            TopicArn=topic_arn, Subject=subject, Message=message_fail
        )
        snapshot.match("publish-no-logs", publish_no_logs)

        # Then enable the SNS Delivery Logs for Lambda on the topic
        aws_client.sns.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="LambdaSuccessFeedbackRoleArn",
            AttributeValue=role_arn,
        )

        aws_client.sns.set_topic_attributes(
            TopicArn=topic_arn,
            AttributeName="LambdaSuccessFeedbackSampleRate",
            AttributeValue="100",
        )

        topic_attributes = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("get-topic-attrs-with-success-feedback", topic_attributes)

        publish_logs = aws_client.sns.publish(
            TopicArn=topic_arn, Subject=subject, Message=message_success
        )
        # we snapshot the publish call to match the messageId to the events
        snapshot.match("publish-logs", publish_logs)

        # TODO: Wait until Lambda function actually executes and not only for SNS logs
        log_group_name = f"sns/{region}/{account_id}/{topic_name}"

        def get_log_events():
            log_streams = aws_client.logs.describe_log_streams(logGroupName=log_group_name)[
                "logStreams"
            ]
            assert len(log_streams) == 1
            log_events = aws_client.logs.get_log_events(
                logGroupName=log_group_name,
                logStreamName=log_streams[0]["logStreamName"],
            )
            assert len(log_events["events"]) == 1
            # the default retention is 30 days, so delete the logGroup to clean up AWS
            with contextlib.suppress(ClientError):
                aws_client.logs.delete_log_group(logGroupName=log_group_name)
            return log_events

        sleep_time = 5 if is_aws_cloud() else 0.3
        events = retry(get_log_events, retries=10, sleep=sleep_time)

        # we need to decode the providerResponse to be able to properly match on the response
        # test would raise an error anyway if it's not a JSON string
        msg = json.loads(events["events"][0]["message"])
        events["events"][0]["message"] = msg
        events["events"][0]["message"]["delivery"]["providerResponse"] = json.loads(
            msg["delivery"]["providerResponse"]
        )

        snapshot.match("delivery-events", events)


class TestSNSRetrospectionEndpoints:
    @markers.aws.only_localstack
    def test_publish_to_platform_endpoint_can_retrospect(
        self,
        sns_create_topic,
        sns_subscription,
        sns_create_platform_application,
        aws_client,
        account_id,
        region_name,
        secondary_region_name,
    ):
        sns_backend = SnsProvider.get_store(account_id, region_name)
        # clean up the saved messages
        sns_backend_endpoint_arns = list(sns_backend.platform_endpoint_messages.keys())
        for saved_endpoint_arn in sns_backend_endpoint_arns:
            sns_backend.platform_endpoint_messages.pop(saved_endpoint_arn, None)

        topic_arn = sns_create_topic()["TopicArn"]
        application_platform_name = f"app-platform-{short_uid()}"

        app_arn = sns_create_platform_application(
            Name=application_platform_name, Platform="APNS", Attributes={}
        )["PlatformApplicationArn"]

        endpoint_arn = aws_client.sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token=short_uid()
        )["EndpointArn"]

        endpoint_arn_2 = aws_client.sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token=short_uid()
        )["EndpointArn"]

        sns_subscription(
            TopicArn=topic_arn,
            Protocol="application",
            Endpoint=endpoint_arn,
        )

        # example message from
        # https://docs.aws.amazon.com/sns/latest/dg/sns-send-custom-platform-specific-payloads-mobile-devices.html
        message = json.dumps({"APNS": json.dumps({"aps": {"content-available": 1}})})
        message_for_topic = {
            "default": "This is the default message which must be present when publishing a message to a topic.",
            "APNS": json.dumps({"aps": {"content-available": 1}}),
        }
        message_for_topic_string = json.dumps(message_for_topic)
        message_attributes = {
            "AWS.SNS.MOBILE.APNS.TOPIC": {
                "DataType": "String",
                "StringValue": "com.amazon.mobile.messaging.myapp",
            },
            "AWS.SNS.MOBILE.APNS.PUSH_TYPE": {
                "DataType": "String",
                "StringValue": "background",
            },
            "AWS.SNS.MOBILE.APNS.PRIORITY": {
                "DataType": "String",
                "StringValue": "5",
            },
        }
        # publish to a topic which has a platform subscribed to it
        aws_client.sns.publish(
            TopicArn=topic_arn,
            Message=message_for_topic_string,
            MessageAttributes=message_attributes,
            MessageStructure="json",
        )
        # publish directly to the platform endpoint
        aws_client.sns.publish(
            TargetArn=endpoint_arn_2,
            Message=message,
            MessageAttributes=message_attributes,
            MessageStructure="json",
        )

        # assert that message has been received
        def check_message():
            assert len(sns_backend.platform_endpoint_messages[endpoint_arn]) > 0

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        msgs_url = config.internal_service_url() + PLATFORM_ENDPOINT_MSGS_ENDPOINT
        api_contents = requests.get(
            msgs_url, params={"region": region_name, "accountId": account_id}
        ).json()
        api_platform_endpoints_msgs = api_contents["platform_endpoint_messages"]

        assert len(api_platform_endpoints_msgs) == 2
        assert len(api_platform_endpoints_msgs[endpoint_arn]) == 1
        assert len(api_platform_endpoints_msgs[endpoint_arn_2]) == 1
        assert api_contents["region"] == region_name

        assert api_platform_endpoints_msgs[endpoint_arn][0]["Message"] == json.dumps(
            message_for_topic["APNS"]
        )
        assert (
            api_platform_endpoints_msgs[endpoint_arn][0]["MessageAttributes"] == message_attributes
        )

        # Ensure you can select the region
        msg_with_region = requests.get(
            msgs_url,
            params={"region": secondary_region_name, "accountId": account_id},
        ).json()
        assert len(msg_with_region["platform_endpoint_messages"]) == 0
        assert msg_with_region["region"] == secondary_region_name

        # Ensure default region is us-east-1
        msg_with_region = requests.get(msgs_url).json()
        assert msg_with_region["region"] == AWS_REGION_US_EAST_1

        # Ensure messages can be filtered by EndpointArn
        api_contents_with_endpoint = requests.get(
            msgs_url,
            params={
                "endpointArn": endpoint_arn,
                "region": region_name,
                "accountId": account_id,
            },
        ).json()
        msgs_with_endpoint = api_contents_with_endpoint["platform_endpoint_messages"]
        assert len(msgs_with_endpoint) == 1
        assert len(msgs_with_endpoint[endpoint_arn]) == 1
        assert api_contents_with_endpoint["region"] == region_name

        # Ensure you can reset the saved messages by EndpointArn
        delete_res = requests.delete(
            msgs_url,
            params={
                "endpointArn": endpoint_arn,
                "region": region_name,
                "accountId": account_id,
            },
        )
        assert delete_res.status_code == 204
        api_contents_with_endpoint = requests.get(
            msgs_url,
            params={
                "endpointArn": endpoint_arn,
                "region": region_name,
                "accountId": account_id,
            },
        ).json()
        msgs_with_endpoint = api_contents_with_endpoint["platform_endpoint_messages"]
        assert len(msgs_with_endpoint[endpoint_arn]) == 0

        # Ensure you can reset the saved messages by region
        delete_res = requests.delete(
            msgs_url, params={"region": region_name, "accountId": account_id}
        )
        assert delete_res.status_code == 204
        msg_with_region = requests.get(
            msgs_url, params={"region": region_name, "accountId": account_id}
        ).json()
        assert not msg_with_region["platform_endpoint_messages"]

    @markers.aws.only_localstack
    def test_publish_sms_can_retrospect(
        self,
        sns_create_topic,
        sns_subscription,
        aws_client,
        account_id,
        region_name,
        secondary_region_name,
    ):
        sns_store = SnsProvider.get_store(account_id, region_name)

        list_of_contacts = [
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
        ]
        phone_number_1 = list_of_contacts[0]
        message = "Good news everyone!"
        topic_arn = sns_create_topic()["TopicArn"]
        for number in list_of_contacts:
            sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=number)

        # clean up the saved messages
        sns_store.sms_messages.clear()

        # publish to a topic which has a PhoneNumbers subscribed to it
        aws_client.sns.publish(Message=message, TopicArn=topic_arn)

        # publish directly to the PhoneNumber
        aws_client.sns.publish(
            PhoneNumber=phone_number_1,
            Message=message,
        )

        # assert that message has been received
        def check_message():
            assert len(sns_store.sms_messages) == 4

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        msgs_url = config.internal_service_url() + SMS_MSGS_ENDPOINT
        api_contents = requests.get(
            msgs_url, params={"region": region_name, "accountId": account_id}
        ).json()
        api_sms_msgs = api_contents["sms_messages"]

        assert len(api_sms_msgs) == 3
        assert len(api_sms_msgs[phone_number_1]) == 2
        assert len(api_sms_msgs[list_of_contacts[1]]) == 1
        assert len(api_sms_msgs[list_of_contacts[2]]) == 1

        assert api_contents["region"] == region_name

        assert api_sms_msgs[phone_number_1][0]["Message"] == "Good news everyone!"

        # Ensure you can select the region
        msg_with_region = requests.get(msgs_url, params={"region": secondary_region_name}).json()
        assert len(msg_with_region["sms_messages"]) == 0
        assert msg_with_region["region"] == secondary_region_name

        # Ensure default region is us-east-1
        msg_with_region = requests.get(msgs_url).json()
        assert msg_with_region["region"] == AWS_REGION_US_EAST_1

        # Ensure messages can be filtered by EndpointArn
        api_contents_with_number = requests.get(
            msgs_url,
            params={
                "phoneNumber": phone_number_1,
                "accountId": account_id,
                "region": region_name,
            },
        ).json()
        msgs_with_number = api_contents_with_number["sms_messages"]
        assert len(msgs_with_number) == 1
        assert len(msgs_with_number[phone_number_1]) == 2
        assert api_contents_with_number["region"] == region_name

        # Ensure you can reset the saved messages by EndpointArn
        delete_res = requests.delete(
            msgs_url,
            params={
                "phoneNumber": phone_number_1,
                "accountId": account_id,
                "region": region_name,
            },
        )
        assert delete_res.status_code == 204
        api_contents_with_number = requests.get(
            msgs_url, params={"phoneNumber": phone_number_1}
        ).json()
        msgs_with_number = api_contents_with_number["sms_messages"]
        assert len(msgs_with_number[phone_number_1]) == 0

        # Ensure you can reset the saved messages by region
        delete_res = requests.delete(
            msgs_url, params={"region": region_name, "accountId": account_id}
        )
        assert delete_res.status_code == 204
        msg_with_region = requests.get(msgs_url, params={"region": region_name}).json()
        assert not msg_with_region["sms_messages"]

    @markers.aws.only_localstack
    def test_subscription_tokens_can_retrospect(
        self,
        sns_create_topic,
        sns_subscription,
        sns_create_http_endpoint,
        aws_client,
        account_id,
        region_name,
    ):
        sns_store = SnsProvider.get_store(account_id, region_name)
        # clean up the saved tokens
        sns_store.subscription_tokens.clear()

        message = "Good news everyone!"
        # Necessitate manual set up to allow external access to endpoint, only in local testing
        topic_arn, subscription_arn, endpoint_url, server = sns_create_http_endpoint()
        assert poll_condition(
            lambda: len(server.log) >= 1,
            timeout=5,
        )
        sub_request, _ = server.log[0]
        payload = sub_request.get_json(force=True)
        assert payload["Type"] == "SubscriptionConfirmation"
        token = payload["Token"]
        server.clear()

        # we won't confirm the subscription, to simulate an external provider that wouldn't be able to access LocalStack
        # try to access the internal to confirm the Token is there
        tokens_base_url = config.internal_service_url() + SUBSCRIPTION_TOKENS_ENDPOINT
        api_contents = requests.get(f"{tokens_base_url}/{subscription_arn}").json()
        assert api_contents["subscription_token"] == token
        assert api_contents["subscription_arn"] == subscription_arn

        # try to send a message to an unconfirmed subscription, assert that the message isn't received
        aws_client.sns.publish(Message=message, TopicArn=topic_arn)

        assert poll_condition(
            lambda: len(server.log) == 0,
            timeout=1,
        )

        aws_client.sns.confirm_subscription(TopicArn=topic_arn, Token=token)
        aws_client.sns.publish(Message=message, TopicArn=topic_arn)
        assert poll_condition(
            lambda: len(server.log) == 1,
            timeout=2,
        )

        wrong_sub_arn = subscription_arn.replace(
            region_name,
            "il-central-1" if region_name != "il-central-1" else "me-south-1",
        )
        wrong_region_req = requests.get(f"{tokens_base_url}/{wrong_sub_arn}")
        assert wrong_region_req.status_code == 404
        assert wrong_region_req.json() == {
            "error": "The provided SubscriptionARN is not found",
            "subscription_arn": wrong_sub_arn,
        }

        # Ensure proper error is raised with wrong ARN
        incorrect_arn_req = requests.get(f"{tokens_base_url}/randomarnhere")
        assert incorrect_arn_req.status_code == 400
        assert incorrect_arn_req.json() == {
            "error": "The provided SubscriptionARN is invalid",
            "subscription_arn": "randomarnhere",
        }
