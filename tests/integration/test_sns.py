# -*- coding: utf-8 -*-

import json
import os
import random
import time

import pytest
import requests
from botocore.exceptions import ClientError

from localstack import config
from localstack.config import external_service_url
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services.generic_proxy import ProxyListener
from localstack.services.infra import start_proxy
from localstack.services.install import SQS_BACKEND_IMPL
from localstack.services.sns.sns_listener import SNSBackend
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    get_free_tcp_port,
    get_service_protocol,
    retry,
    short_uid,
    to_str,
    wait_for_port_open,
)
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .lambdas import lambda_integration
from .test_lambda import LAMBDA_RUNTIME_PYTHON36, TEST_LAMBDA_LIBS, TEST_LAMBDA_PYTHON

TEST_TOPIC_NAME = "TestTopic_snsTest"
TEST_QUEUE_NAME = "TestQueue_snsTest"
TEST_QUEUE_DLQ_NAME = "TestQueue_DLQ_snsTest"
TEST_TOPIC_NAME_2 = "topic-test-2"

PUBLICATION_TIMEOUT = 0.500
PUBLICATION_RETRIES = 4

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_ECHO_FILE = os.path.join(THIS_FOLDER, "lambdas", "lambda_echo.py")


@pytest.fixture(scope="class")
def setup(request):
    request.cls.sqs_client = aws_stack.create_external_boto_client("sqs")
    request.cls.sns_client = aws_stack.create_external_boto_client("sns")
    request.cls.topic_arn = request.cls.sns_client.create_topic(Name=TEST_TOPIC_NAME)["TopicArn"]
    request.cls.queue_url = request.cls.sqs_client.create_queue(QueueName=TEST_QUEUE_NAME)[
        "QueueUrl"
    ]
    request.cls.dlq_url = request.cls.sqs_client.create_queue(QueueName=TEST_QUEUE_DLQ_NAME)[
        "QueueUrl"
    ]

    yield

    request.cls.sqs_client.delete_queue(QueueUrl=request.cls.queue_url)
    request.cls.sqs_client.delete_queue(QueueUrl=request.cls.dlq_url)
    request.cls.sns_client.delete_topic(TopicArn=request.cls.topic_arn)


@pytest.mark.usefixtures("setup")
class TestSNS:
    def test_publish_unicode_chars(self):
        # connect an SNS topic to a new SQS queue
        _, queue_arn, queue_url = self._create_queue()
        self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol="sqs", Endpoint=queue_arn)

        # publish message to SNS, receive it from SQS, assert that messages are equal
        message = 'ö§a1"_!?,. £$-'
        self.sns_client.publish(TopicArn=self.topic_arn, Message=message)

        def check_message():
            msgs = self.sqs_client.receive_message(QueueUrl=queue_url)
            msg_received = msgs["Messages"][0]
            msg_received = json.loads(to_str(msg_received["Body"]))
            msg_received = msg_received["Message"]
            assert message == msg_received

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_subscribe_http_endpoint(self):
        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        wait_for_port_open(local_port)
        queue_arn = "%s://localhost:%s" % (get_service_protocol(), local_port)
        self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol="http", Endpoint=queue_arn)

        def received():
            assert records[0][0]["Type"] == "SubscriptionConfirmation"
            assert records[0][1]["x-amz-sns-message-type"] == "SubscriptionConfirmation"

            token = records[0][0]["Token"]
            subscribe_url = records[0][0]["SubscribeURL"]

            assert subscribe_url == (
                "%s/?Action=ConfirmSubscription&TopicArn=%s&Token=%s"
                % (external_service_url("sns"), self.topic_arn, token)
            )

            assert "Signature" in records[0][0]
            assert "SigningCertURL" in records[0][0]

        retry(received, retries=5, sleep=1)
        proxy.stop()

    def test_subscribe_with_invalid_protocol(self):
        topic_arn = self.sns_client.create_topic(Name=TEST_TOPIC_NAME_2)["TopicArn"]

        with pytest.raises(ClientError) as e:
            self.sns_client.subscribe(
                TopicArn=topic_arn, Protocol="test-protocol", Endpoint="localstack@yopmail.com"
            )

        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert e.value.response["Error"]["Code"] == "InvalidParameter"

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)

    def test_attribute_raw_subscribe(self):
        # create SNS topic and connect it to an SQS queue
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME)
        self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
            Attributes={"RawMessageDelivery": "true"},
        )

        # fetch subscription information
        subscription_list = self.sns_client.list_subscriptions()

        subscription_arn = ""
        for subscription in subscription_list["Subscriptions"]:
            if subscription["TopicArn"] == self.topic_arn:
                subscription_arn = subscription["SubscriptionArn"]
        actual_attributes = self.sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )["Attributes"]

        # assert the attributes are well set
        assert actual_attributes["RawMessageDelivery"]

        # publish message to SNS, receive it from SQS, assert that messages are equal and that they are Raw
        message = "This is a test message"
        binary_attribute = b"\x02\x03\x04"
        # extending this test case to test support for binary message attribute data
        # https://github.com/localstack/localstack/issues/2432
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"store": {"DataType": "Binary", "BinaryValue": binary_attribute}},
        )

        def check_message():
            msgs = self.sqs_client.receive_message(
                QueueUrl=self.queue_url, MessageAttributeNames=["All"]
            )
            msg_received = msgs["Messages"][0]

            assert message == msg_received["Body"]
            assert binary_attribute == msg_received["MessageAttributes"]["store"]["BinaryValue"]

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_filter_policy(self):
        # connect SNS topic to an SQS queue
        queue_name, queue_arn, queue_url = self._create_queue()

        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
            Attributes={"FilterPolicy": json.dumps(filter_policy)},
        )

        # get number of messages
        num_msgs_0 = len(self.sqs_client.receive_message(QueueUrl=queue_url).get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99"}},
        )

        def check_message():
            num_msgs_1 = len(
                self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)["Messages"]
            )
            assert num_msgs_1 == (num_msgs_0 + 1)
            return num_msgs_1

        num_msgs_1 = retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        def check_message2():
            num_msgs_2 = len(
                self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)["Messages"]
            )
            assert num_msgs_2 == num_msgs_1
            return num_msgs_2

        retry(check_message2, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_exists_filter_policy(self):
        # connect SNS topic to an SQS queue
        queue_name, queue_arn, queue_url = self._create_queue()
        filter_policy = {"store": [{"exists": True}]}

        def do_subscribe(self, filter_policy, queue_arn):
            self.sns_client.subscribe(
                TopicArn=self.topic_arn,
                Protocol="sqs",
                Endpoint=queue_arn,
                Attributes={"FilterPolicy": json.dumps(filter_policy)},
            )

        do_subscribe(self, filter_policy, queue_arn)

        # get number of messages
        num_msgs_0 = len(self.sqs_client.receive_message(QueueUrl=queue_url).get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )

        def check_message1():
            num_msgs_1 = len(
                self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)["Messages"]
            )
            assert num_msgs_1 == (num_msgs_0 + 1)
            return num_msgs_1

        num_msgs_1 = retry(check_message1, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        def check_message2():
            num_msgs_2 = len(
                self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)["Messages"]
            )
            assert num_msgs_2 == num_msgs_1
            return num_msgs_2

        retry(check_message2, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # test with exist operator set to false.
        queue_arn = aws_stack.sqs_queue_arn(TEST_QUEUE_NAME)
        filter_policy = {"store": [{"exists": False}]}
        do_subscribe(self, filter_policy, queue_arn)
        # get number of messages
        num_msgs_0 = len(
            self.sqs_client.receive_message(QueueUrl=self.queue_url).get("Messages", [])
        )

        # publish message with the attribute and see if its getting filtered.
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )

        def check_message():
            num_msgs_1 = len(
                self.sqs_client.receive_message(QueueUrl=self.queue_url, VisibilityTimeout=0).get(
                    "Messages", []
                )
            )
            assert num_msgs_1 == num_msgs_0
            return num_msgs_1

        num_msgs_1 = retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # publish message that without the attribute and see if its getting filtered.
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        def check_message3():
            num_msgs_2 = len(
                self.sqs_client.receive_message(QueueUrl=self.queue_url, VisibilityTimeout=0).get(
                    "Messages", []
                )
            )
            assert num_msgs_2 == num_msgs_1
            return num_msgs_2

        retry(check_message3, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_subscribe_sqs_queue(self):
        _, queue_arn, queue_url = self._create_queue()

        # publish message
        subscription = self._publish_sns_message_with_attrs(queue_arn, "sqs")

        # assert that message is received
        def check_message():
            messages = self.sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)[
                "Messages"
            ]
            assert json.loads(messages[0]["Body"])["MessageAttributes"]["attr1"]["Value"] == "99.12"

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        self.sqs_client.delete_queue(QueueUrl=queue_url)
        self.sns_client.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])

    def test_subscribe_platform_endpoint(self):
        sns = self.sns_client
        sns_backend = SNSBackend.get()
        app_arn = sns.create_platform_application(Name="app1", Platform="p1", Attributes={})[
            "PlatformApplicationArn"
        ]
        platform_arn = sns.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token="token_1"
        )["EndpointArn"]
        subscription = self._publish_sns_message_with_attrs(platform_arn, "application")

        # assert that message has been received
        def check_message():
            assert len(sns_backend.platform_endpoint_messages[platform_arn]) > 0

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        sns.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        sns.delete_endpoint(EndpointArn=platform_arn)
        sns.delete_platform_application(PlatformApplicationArn=app_arn)

    def _publish_sns_message_with_attrs(self, endpoint_arn, protocol):
        # create subscription with filter policy
        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn,
            Protocol=protocol,
            Endpoint=endpoint_arn,
            Attributes={"FilterPolicy": json.dumps(filter_policy)},
        )
        # publish message that satisfies the filter policy
        message = "This is a test message"
        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )
        time.sleep(PUBLICATION_TIMEOUT)
        return subscription

    def test_unknown_topic_publish(self):
        fake_arn = "arn:aws:sns:us-east-1:123456789012:i_dont_exist"
        message = "This is a test message"

        with pytest.raises(ClientError) as e:
            self.sns_client.publish(TopicArn=fake_arn, Message=message)

        assert e.value.response["Error"]["Code"] == "NotFound"
        assert e.value.response["Error"]["Message"] == "Topic does not exist"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

    def test_publish_sms(self):
        response = self.sns_client.publish(PhoneNumber="+33000000000", Message="This is a SMS")
        assert "MessageId" in response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_publish_target(self):
        response = self.sns_client.publish(
            TargetArn="arn:aws:sns:us-east-1:000000000000:endpoint/APNS/abcdef/0f7d5971-aa8b-4bd5-b585-0826e9f93a66",
            Message="This is a push notification",
        )
        assert "MessageId" in response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_tags(self):
        self.sns_client.tag_resource(
            ResourceArn=self.topic_arn,
            Tags=[
                {"Key": "123", "Value": "abc"},
                {"Key": "456", "Value": "def"},
                {"Key": "456", "Value": "def"},
            ],
        )

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        distinct_tags = [
            tag for idx, tag in enumerate(tags["Tags"]) if tag not in tags["Tags"][:idx]
        ]
        # test for duplicate tags
        assert len(tags["Tags"]) == len(distinct_tags)
        assert len(tags["Tags"]) == 2
        assert tags["Tags"][0]["Key"] == "123"
        assert tags["Tags"][0]["Value"] == "abc"
        assert tags["Tags"][1]["Key"] == "456"
        assert tags["Tags"][1]["Value"] == "def"

        self.sns_client.untag_resource(ResourceArn=self.topic_arn, TagKeys=["123"])

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        assert len(tags["Tags"]) == 1
        assert tags["Tags"][0]["Key"] == "456"
        assert tags["Tags"][0]["Value"] == "def"

        self.sns_client.tag_resource(
            ResourceArn=self.topic_arn, Tags=[{"Key": "456", "Value": "pqr"}]
        )

        tags = self.sns_client.list_tags_for_resource(ResourceArn=self.topic_arn)
        assert len(tags["Tags"]) == 1
        assert tags["Tags"][0]["Key"] == "456"
        assert tags["Tags"][0]["Value"] == "pqr"

    def test_topic_subscription(self):
        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn, Protocol="email", Endpoint="localstack@yopmail.com"
        )
        sns_backend = SNSBackend.get()

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_obj = sns_backend.subscription_status[subscription_arn]
            assert subscription_obj["Status"] == "Not Subscribed"

            _token = subscription_obj["Token"]
            self.sns_client.confirm_subscription(TopicArn=self.topic_arn, Token=_token)
            assert subscription_obj["Status"] == "Subscribed"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_dead_letter_queue(self):
        lambda_name = "test-%s" % short_uid()
        lambda_arn = aws_stack.lambda_function_arn(lambda_name)
        topic_name = "test-%s" % short_uid()
        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]
        queue_name = "test-%s" % short_uid()
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        testutil.create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            DeadLetterConfig={"TargetArn": queue_arn},
        )
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn)

        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }
        self.sns_client.publish(TopicArn=topic_arn, Message=json.dumps(payload))

        def receive_dlq():
            result = self.sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"]
            )
            msg_attrs = result["Messages"][0]["MessageAttributes"]
            assert len(result["Messages"]) > 0
            assert "RequestID" in msg_attrs
            assert "ErrorCode" in msg_attrs
            assert "ErrorMessage" in msg_attrs

        retry(receive_dlq, retries=8, sleep=2)

    def unsubscribe_all_from_sns(self):
        for subscription_arn in self.sns_client.list_subscriptions()["Subscriptions"]:
            self.sns_client.unsubscribe(SubscriptionArn=subscription_arn["SubscriptionArn"])

    def test_redrive_policy_http_subscription(self):
        self.unsubscribe_all_from_sns()

        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 200

        records = []
        local_port = get_free_tcp_port()
        proxy = start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
        wait_for_port_open(local_port)
        http_endpoint = "%s://localhost:%s" % (get_service_protocol(), local_port)

        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn, Protocol="http", Endpoint=http_endpoint
        )
        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps(
                {"deadLetterTargetArn": aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)}
            ),
        )

        proxy.stop()
        # for some reason, it takes a long time to stop the proxy thread -> TODO investigate
        time.sleep(5)

        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=json.dumps({"message": "test_redrive_policy"}),
        )

        def receive_dlq():
            result = self.sqs_client.receive_message(
                QueueUrl=self.dlq_url, MessageAttributeNames=["All"]
            )
            assert len(result["Messages"]) > 0
            assert (
                json.loads(json.loads(result["Messages"][0]["Body"])["Message"][0])["message"]
                == "test_redrive_policy"
            )

        retry(receive_dlq, retries=7, sleep=2.5)

    def test_redrive_policy_lambda_subscription(self):
        self.unsubscribe_all_from_sns()

        lambda_name = "test-%s" % short_uid()
        lambda_arn = aws_stack.lambda_function_arn(lambda_name)

        testutil.create_lambda_function(
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )

        subscription = self.sns_client.subscribe(
            TopicArn=self.topic_arn, Protocol="lambda", Endpoint=lambda_arn
        )

        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps(
                {"deadLetterTargetArn": aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)}
            ),
        )
        testutil.delete_lambda_function(lambda_name)

        self.sns_client.publish(
            TopicArn=self.topic_arn,
            Message=json.dumps({"message": "test_redrive_policy"}),
        )

        def receive_dlq():
            result = self.sqs_client.receive_message(
                QueueUrl=self.dlq_url, MessageAttributeNames=["All"]
            )
            assert len(result["Messages"]) > 0
            assert (
                json.loads(json.loads(result["Messages"][0]["Body"])["Message"][0])["message"]
                == "test_redrive_policy"
            )

        retry(receive_dlq, retries=10, sleep=2)

    def test_redrive_policy_queue_subscription(self):
        self.unsubscribe_all_from_sns()

        topic_arn = self.sns_client.create_topic(Name="topic-%s" % short_uid())["TopicArn"]
        invalid_queue_arn = aws_stack.sqs_queue_arn("invalid_queue")
        # subscribe with an invalid queue ARN, to trigger event on DLQ below
        subscription = self.sns_client.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=invalid_queue_arn
        )

        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps(
                {"deadLetterTargetArn": aws_stack.sqs_queue_arn(TEST_QUEUE_DLQ_NAME)}
            ),
        )

        self.sns_client.publish(
            TopicArn=topic_arn, Message=json.dumps({"message": "test_redrive_policy"})
        )

        def receive_dlq():
            result = self.sqs_client.receive_message(
                QueueUrl=self.dlq_url, MessageAttributeNames=["All"]
            )
            assert len(result["Messages"]) > 0
            assert (
                json.loads(json.loads(result["Messages"][0]["Body"])["Message"][0])["message"]
                == "test_redrive_policy"
            )

        retry(receive_dlq, retries=10, sleep=2)

    def test_publish_with_empty_subject(self):
        topic_arn = self.sns_client.create_topic(Name=TEST_TOPIC_NAME_2)["TopicArn"]

        # Publish without subject
        rs = self.sns_client.publish(
            TopicArn=topic_arn, Message=json.dumps({"message": "test_publish"})
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            self.sns_client.publish(
                TopicArn=topic_arn,
                Subject="",
                Message=json.dumps({"message": "test_publish"}),
            )

        assert e.value.response["Error"]["Code"] == "InvalidParameter"

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)

    def test_create_topic_test_arn(self):
        response = self.sns_client.create_topic(Name=TEST_TOPIC_NAME)
        topic_arn_params = response["TopicArn"].split(":")
        testutil.response_arn_matches_partition(self.sns_client, response["TopicArn"])
        assert topic_arn_params[4] == TEST_AWS_ACCOUNT_ID
        assert topic_arn_params[5] == TEST_TOPIC_NAME

    def test_publish_message_by_target_arn(self):
        self.unsubscribe_all_from_sns()

        topic_name = "queue-{}".format(short_uid())
        func_name = "lambda-%s" % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_ECHO_FILE,
            func_name=func_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        lambda_arn = aws_stack.lambda_function_arn(func_name)

        subscription_arn = self.sns_client.subscribe(
            TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn
        )["SubscriptionArn"]

        self.sns_client.publish(
            TopicArn=topic_arn, Message="test_message_1", Subject="test subject"
        )

        # Lambda invoked 1 time
        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=func_name,
            expected_length=1,
        )

        message = events[0]["Records"][0]
        assert message["EventSubscriptionArn"] == subscription_arn

        self.sns_client.publish(
            TargetArn=topic_arn, Message="test_message_2", Subject="test subject"
        )

        events = retry(
            check_expected_lambda_log_events_length,
            retries=3,
            sleep=1,
            function_name=func_name,
            expected_length=2,
        )
        # Lambda invoked 1 more time
        assert len(events) == 2

        for event in events:
            message = event["Records"][0]
            assert message["EventSubscriptionArn"] == subscription_arn

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        lambda_client = aws_stack.create_external_boto_client("lambda")
        lambda_client.delete_function(FunctionName=func_name)

    def test_publish_message_after_subscribe_topic(self):
        self.unsubscribe_all_from_sns()

        topic_name = "queue-{}".format(short_uid())
        queue_name = "test-%s" % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        rs = self.sns_client.publish(
            TopicArn=topic_arn, Subject="test subject", Message="test_message_1"
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        message_subject = "sqs subject"
        message_body = "test_message_2"

        rs = self.sns_client.publish(
            TopicArn=topic_arn, Subject=message_subject, Message=message_body
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        message_id = rs["MessageId"]

        def get_message(q_url):
            resp = self.sqs_client.receive_message(QueueUrl=q_url)
            return json.loads(resp["Messages"][0]["Body"])

        message = retry(get_message, retries=3, sleep=2, q_url=queue_url)
        assert message["MessageId"] == message_id
        assert message["Subject"] == message_subject
        assert message["Message"] == message_body

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_create_duplicate_topic_with_different_tags(self):
        topic_name = "test-%s" % short_uid()
        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]

        with pytest.raises(ClientError) as e:
            self.sns_client.create_topic(Name=topic_name, Tags=[{"Key": "456", "Value": "pqr"}])

        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["Error"]["Message"] == "Topic already exists with different tags"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)

    def test_create_duplicate_topic_check_idempotentness(self):
        topic_name = "test-%s" % short_uid()
        tags = [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}]
        kwargs = [
            {"Tags": tags},  # to create topic with two tags
            {"Tags": tags},  # to create the same topic again with same tags
            {"Tags": [tags[0]]},  # to create the same topic again with one of the tags from above
            {"Tags": []},  # to create the same topic again with no tags
        ]
        responses = []
        for arg in kwargs:
            responses.append(self.sns_client.create_topic(Name=topic_name, **arg))
        # assert TopicArn is returned by all the above create_topic calls
        for i in range(len(responses)):
            assert "TopicArn" in responses[i]
        # clean up
        self.sns_client.delete_topic(TopicArn=responses[0]["TopicArn"])

    def test_create_platform_endpoint_check_idempotentness(self):
        response = self.sns_client.create_platform_application(
            Name="test-%s" % short_uid(),
            Platform="GCM",
            Attributes={"PlatformCredential": "123"},
        )
        kwargs_list = [
            {"Token": "test1", "CustomUserData": "test-data"},
            {"Token": "test1", "CustomUserData": "test-data"},
            {"Token": "test1"},
            {"Token": "test1"},
        ]
        platform_arn = response["PlatformApplicationArn"]
        responses = []
        for kwargs in kwargs_list:
            responses.append(
                self.sns_client.create_platform_endpoint(
                    PlatformApplicationArn=platform_arn, **kwargs
                )
            )
        # Assert endpointarn is returned in every call create platform call
        for i in range(len(responses)):
            assert "EndpointArn" in responses[i]
        endpoint_arn = responses[0]["EndpointArn"]
        # clean up
        self.sns_client.delete_endpoint(EndpointArn=endpoint_arn)
        self.sns_client.delete_platform_application(PlatformApplicationArn=platform_arn)

    def test_publish_by_path_parameters(self):
        topic_name = "topic-{}".format(short_uid())
        queue_name = "queue-{}".format(short_uid())

        message = "test message {}".format(short_uid())
        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]

        base_url = "{}://{}:{}".format(
            get_service_protocol(), config.LOCALSTACK_HOSTNAME, config.PORT_SNS
        )
        path = "Action=Publish&Version=2010-03-31&TopicArn={}&Message={}".format(topic_arn, message)

        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        r = requests.post(
            url="{}/?{}".format(base_url, path),
            headers=aws_stack.mock_aws_request_headers("sns"),
        )
        assert r.status_code == 200

        def get_notification(q_url):
            resp = self.sqs_client.receive_message(QueueUrl=q_url)
            return json.loads(resp["Messages"][0]["Body"])

        notification = retry(get_notification, retries=3, sleep=2, q_url=queue_url)
        assert notification["TopicArn"] == topic_arn
        assert notification["Message"] == message

        # clean up
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_multiple_subscriptions_http_endpoint(self):
        self.unsubscribe_all_from_sns()

        # create HTTP endpoint and connect it to SNS topic
        class MyUpdateListener(ProxyListener):
            def forward_request(self, method, path, data, headers):
                records.append((json.loads(to_str(data)), headers))
                return 429

        number_of_subscriptions = 4
        records = []
        proxies = []

        for _ in range(number_of_subscriptions):
            local_port = get_free_tcp_port()
            proxies.append(
                start_proxy(local_port, backend_url=None, update_listener=MyUpdateListener())
            )
            wait_for_port_open(local_port)
            http_endpoint = "%s://localhost:%s" % (get_service_protocol(), local_port)
            self.sns_client.subscribe(
                TopicArn=self.topic_arn, Protocol="http", Endpoint=http_endpoint
            )

        # fetch subscription information
        subscription_list = self.sns_client.list_subscriptions()
        assert subscription_list["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(subscription_list["Subscriptions"]) == number_of_subscriptions
        assert number_of_subscriptions == len(records)

        for proxy in proxies:
            proxy.stop()

    def _create_queue(self):
        queue_name = "queue-%s" % short_uid()
        queue_arn = aws_stack.sqs_queue_arn(queue_name)
        queue_url = self.sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        return queue_name, queue_arn, queue_url

    def test_publish_sms_endpoint(self):
        list_of_contacts = [
            "+%d" % random.randint(100000000, 9999999999),
            "+%d" % random.randint(100000000, 9999999999),
            "+%d" % random.randint(100000000, 9999999999),
        ]
        message = "Good news everyone!"

        for number in list_of_contacts:
            self.sns_client.subscribe(TopicArn=self.topic_arn, Protocol="sms", Endpoint=number)

        self.sns_client.publish(Message=message, TopicArn=self.topic_arn)

        sns_backend = SNSBackend.get()

        def check_messages():
            sms_messages = sns_backend.sms_messages
            for contact in list_of_contacts:
                sms_was_found = False
                for message in sms_messages:
                    if message["endpoint"] == contact:
                        sms_was_found = True
                        break

                assert sms_was_found

        retry(check_messages, sleep=0.5)

    def test_publish_sqs_from_sns(self):
        topic = self.sns_client.create_topic(Name="test_topic3")
        topic_arn = topic["TopicArn"]
        test_queue = self.sqs_client.create_queue(QueueName="test_queue3")

        queue_url = test_queue["QueueUrl"]
        subscription_arn = self.sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_url,
            Attributes={"RawMessageDelivery": "true"},
        )["SubscriptionArn"]
        self.sns_client.publish(
            TargetArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )

        def get_message_with_attributes(queue_url):
            response = self.sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"]
            )
            assert response["Messages"][0]["MessageAttributes"] == {
                "attr1": {"DataType": "Number", "StringValue": "99.12"}
            }
            self.sqs_client.delete_message(
                QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
            )

        retry(get_message_with_attributes, retries=3, sleep=10, queue_url=queue_url)

        self.sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="false",
        )
        self.sns_client.publish(
            TargetArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "100.12"}},
        )

        def get_message_without_attributes(queue_url):
            response = self.sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"]
            )
            assert response["Messages"][0].get("MessageAttributes") is None
            assert "100.12" in response["Messages"][0]["Body"]

            self.sqs_client.delete_message(
                QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
            )

        retry(get_message_without_attributes, retries=3, sleep=10, queue_url=queue_url)

    def test_publish_batch_messages_from_sns_to_sqs(self):
        topic = self.sns_client.create_topic(Name="test_topic3")
        topic_arn = topic["TopicArn"]
        test_queue = self.sqs_client.create_queue(QueueName="test_queue3")

        queue_url = test_queue["QueueUrl"]
        self.sns_client.subscribe(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_url,
            Attributes={"RawMessageDelivery": "true"},
        )

        publish_batch_response = self.sns_client.publish_batch(
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
            ],
        )

        assert "Successful" in publish_batch_response
        assert "Failed" in publish_batch_response

        for successful_resp in publish_batch_response["Successful"]:
            assert "Id" in successful_resp
            assert "MessageId" in successful_resp

        def get_messages(queue_url):
            response = self.sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"], MaxNumberOfMessages=10
            )
            assert len(response["Messages"]) == 3
            for message in response["Messages"]:
                assert "Body" in message

                if message["Body"] == "Test Message with two attributes":
                    assert len(message["MessageAttributes"]) == 2
                    assert message["MessageAttributes"]["attr1"] == {
                        "StringValue": "99.12",
                        "DataType": "Number",
                    }
                    assert message["MessageAttributes"]["attr2"] == {
                        "StringValue": "109.12",
                        "DataType": "Number",
                    }

                elif message["Body"] == "Test Message with one attribute":
                    assert len(message["MessageAttributes"]) == 1
                    assert message["MessageAttributes"]["attr1"] == {
                        "StringValue": "19.12",
                        "DataType": "Number",
                    }

                elif message["Body"] == "Test Message without attribute":
                    assert message.get("MessageAttributes") is None

        retry(get_messages, retries=5, sleep=1, queue_url=queue_url)

    def add_xray_header(self, request, **kwargs):
        request.headers[
            "X-Amzn-Trace-Id"
        ] = "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"

    def test_publish_sqs_from_sns_with_xray_propagation(self):
        if SQS_BACKEND_IMPL != "elasticmq":
            pytest.skip("not using elasticmq as SQS backend")

        self.sns_client.meta.events.register("before-send.sns.Publish", self.add_xray_header)

        topic = self.sns_client.create_topic(Name="test_topic4")
        topic_arn = topic["TopicArn"]
        test_queue = self.sqs_client.create_queue(QueueName="test_queue4")

        queue_url = test_queue["QueueUrl"]
        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_url)
        self.sns_client.publish(TargetArn=topic_arn, Message="X-Ray propagation test msg")

        response = self.sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["SentTimestamp", "AWSTraceHeader"],
            MaxNumberOfMessages=1,
            MessageAttributeNames=["All"],
            VisibilityTimeout=2,
            WaitTimeSeconds=2,
        )

        assert len(response["Messages"]) == 1
        message = response["Messages"][0]
        assert "Attributes" in message
        assert "AWSTraceHeader" in message["Attributes"]
        assert (
            message["Attributes"]["AWSTraceHeader"]
            == "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"
        )

    def test_create_topic_after_delete_with_new_tags(self):
        topic_name = "test-%s" % short_uid()
        topic = self.sns_client.create_topic(
            Name=topic_name, Tags=[{"Key": "Name", "Value": "pqr"}]
        )
        self.sns_client.delete_topic(TopicArn=topic["TopicArn"])

        topic1 = self.sns_client.create_topic(
            Name=topic_name, Tags=[{"Key": "Name", "Value": "abc"}]
        )
        assert topic["TopicArn"] == topic1["TopicArn"]

        # cleanup
        self.sns_client.delete_topic(TopicArn=topic1["TopicArn"])

    def test_not_found_error_on_get_subscription_attributes(self):
        topic_name = "queue-{}".format(short_uid())
        queue_name = "test-%s" % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]
        queue = self.sqs_client.create_queue(QueueName=queue_name)

        queue_url = queue["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        subscription = self.sns_client.subscribe(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn
        )

        subscription_attributes = self.sns_client.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"]
        )

        assert (
            subscription_attributes.get("Attributes").get("SubscriptionArn")
            == subscription["SubscriptionArn"]
        )

        self.sns_client.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])

        with pytest.raises(ClientError) as e:
            self.sns_client.get_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"]
            )

        assert e.value.response["Error"]["Code"] == "NotFound"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

        # cleanup
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_message_to_fifo_sqs(self):
        topic_name = "topic-{}.fifo".format(short_uid())
        queue_name = "queue-%s.fifo" % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name, Attributes={"FifoTopic": "true"})[
            "TopicArn"
        ]
        queue = self.sqs_client.create_queue(
            QueueName=queue_name,
            Attributes={"FifoQueue": "true"},
        )

        queue_url = queue["QueueUrl"]
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        self.sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        message = "Test"
        self.sns_client.publish(TopicArn=topic_arn, Message=message, MessageGroupId=short_uid())

        def get_message():
            received = self.sqs_client.receive_message(QueueUrl=queue_url)["Messages"][0]["Body"]
            assert json.loads(received)["Message"] == message

        retry(get_message, retries=5, sleep=2)

        # cleanup
        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sqs_client.delete_queue(QueueUrl=queue_url)

    def test_validations_for_fifo(self):
        topic_name = "topic-{}".format(short_uid())
        fifo_topic_name = "topic-{}.fifo".format(short_uid())
        fifo_queue_name = "queue-%s.fifo" % short_uid()

        topic_arn = self.sns_client.create_topic(Name=topic_name)["TopicArn"]

        fifo_topic_arn = self.sns_client.create_topic(
            Name=fifo_topic_name, Attributes={"FifoTopic": "true"}
        )["TopicArn"]

        fifo_queue_url = self.sqs_client.create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )["QueueUrl"]

        fifo_queue_arn = aws_stack.sqs_queue_arn(fifo_queue_name)

        with pytest.raises(ClientError) as e:
            self.sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=fifo_queue_arn)

        assert e.match("standard SNS topic")

        with pytest.raises(ClientError) as e:
            self.sns_client.publish(TopicArn=fifo_topic_arn, Message="test")

        assert e.match("MessageGroupId")

        self.sns_client.delete_topic(TopicArn=topic_arn)
        self.sns_client.delete_topic(TopicArn=fifo_topic_arn)
        self.sqs_client.delete_queue(QueueUrl=fifo_queue_url)


def test_empty_sns_message(sns_client, sqs_client, sns_topic, sqs_queue):
    topic_arn = sns_topic["Attributes"]["TopicArn"]
    queue_arn = sqs_client.get_queue_attributes(QueueUrl=sqs_queue, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    sns_client.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    with pytest.raises(ClientError) as e:
        sns_client.publish(Message="", TopicArn=topic_arn)
    assert e.match("Empty message")
    assert (
        sqs_client.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"]["ApproximateNumberOfMessages"]
        == "0"
    )
