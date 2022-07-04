# -*- coding: utf-8 -*-
import json
import queue
import random
from base64 import b64encode

import pytest
import requests
import xmltodict
from botocore.exceptions import ClientError
from pytest_httpserver import HTTPServer
from werkzeug import Response

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.services.install import SQS_BACKEND_IMPL
from localstack.services.sns.provider import SNSBackend
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.net import wait_for_port_closed, wait_for_port_open
from localstack.utils.strings import short_uid, to_str
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .awslambda.functions import lambda_integration
from .awslambda.test_lambda import (
    LAMBDA_RUNTIME_PYTHON36,
    TEST_LAMBDA_FUNCTION_PREFIX,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

PUBLICATION_TIMEOUT = 0.500
PUBLICATION_RETRIES = 4


class TestSNSSubscription:
    def test_python_lambda_subscribe_sns_topic(
        self,
        create_lambda_function,
        sns_client,
        lambda_su_role,
        sns_topic,
        logs_client,
        lambda_client,
        sqs_client,
        sns_subscription,
    ):
        function_name = f"{TEST_LAMBDA_FUNCTION_PREFIX}-{short_uid()}"
        permission_id = f"test-statement-{short_uid()}"
        subject = "[Subject] Test subject"
        message = "Hello world."
        topic_arn = sns_topic["Attributes"]["TopicArn"]

        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            role=lambda_su_role,
        )
        lambda_arn = lambda_creation_response["CreateFunctionResponse"]["FunctionArn"]
        lambda_client.add_permission(
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
            subscription_attrs = sns_client.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        sns_client.publish(TopicArn=topic_arn, Subject=subject, Message=message)

        events = retry(
            check_expected_lambda_log_events_length,
            retries=10,
            sleep=1,
            function_name=function_name,
            expected_length=1,
            regex_filter="Records.*Sns",
            logs_client=logs_client,
        )
        notification = events[0]["Records"][0]["Sns"]
        assert "Subject" in notification
        assert subject == notification["Subject"]


class TestSNSProvider:
    @pytest.mark.aws_validated
    def test_publish_unicode_chars(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_client,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        # publish message to SNS, receive it from SQS, assert that messages are equal
        message = 'ö§a1"_!?,. £$-'
        sns_client.publish(TopicArn=topic_arn, Message=message)

        response = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        msg_received = response["Messages"][0]
        msg_received = json.loads(to_str(msg_received["Body"]))
        msg_received = msg_received["Message"]
        assert message == msg_received

    def test_subscribe_with_invalid_protocol(self, sns_client, sns_create_topic, sns_subscription):
        topic_arn = sns_create_topic()["TopicArn"]

        with pytest.raises(ClientError) as e:
            sns_subscription(
                TopicArn=topic_arn, Protocol="test-protocol", Endpoint="localstack@yopmail.com"
            )

        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
        assert e.value.response["Error"]["Code"] == "InvalidParameter"

    @pytest.mark.aws_validated
    def test_attribute_raw_subscribe(
        self,
        sqs_client,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )

        actual_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )["Attributes"]

        # assert the attributes are well set
        assert actual_attributes["RawMessageDelivery"]

        # publish message to SNS, receive it from SQS, assert that messages are equal and that they are Raw
        message = "This is a test message"
        binary_attribute = b"\x02\x03\x04"
        # extending this test case to test support for binary message attribute data
        # https://github.com/localstack/localstack/issues/2432
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"store": {"DataType": "Binary", "BinaryValue": binary_attribute}},
        )

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        msg_received = response["Messages"][0]
        assert message == msg_received["Body"]
        # MessageAttributes are attached to the message when RawDelivery is true
        assert binary_attribute == msg_received["MessageAttributes"]["store"]["BinaryValue"]

    @pytest.mark.aws_validated
    def test_filter_policy(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        # get number of messages
        num_msgs_0 = len(
            sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0).get("Messages", [])
        )

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        message_attributes = {"attr1": {"DataType": "Number", "StringValue": "99"}}
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes=message_attributes,
        )

        msgs_1 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )["Messages"]
        num_msgs_1 = len(msgs_1)
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This is another test message"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        num_msgs_2 = len(
            sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4)[
                "Messages"
            ]
        )
        assert num_msgs_2 == num_msgs_1

    @pytest.mark.aws_validated
    def test_exists_filter_policy(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        filter_policy = {"store": [{"exists": True}]}
        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        # get number of messages
        num_msgs_0 = len(
            sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0).get("Messages", [])
        )

        # publish message that satisfies the filter policy, assert that message is received
        message_1 = f"message-{short_uid()}"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_1,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )
        msgs_1 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )["Messages"]

        num_msgs_1 = len(msgs_1)
        assert message_1 == json.loads(msgs_1[0]["Body"])["Message"]
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_2 = f"message-{short_uid()}"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_2,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        msgs_2 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )["Messages"]
        num_msgs_2 = len(msgs_2)
        # assert that it's still the same message that #1
        assert json.loads(msgs_2[0]["Body"])["Message"] == message_1
        assert num_msgs_2 == num_msgs_1

        # delete first message
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs_1[0]["ReceiptHandle"])

        # test with exist operator set to false.
        filter_policy = json.dumps({"store": [{"exists": False}]})
        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="FilterPolicy",
            AttributeValue=filter_policy,
        )

        def get_filter_policy():
            subscription_attrs = sns_client.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            return subscription_attrs["Attributes"]["FilterPolicy"] == filter_policy

        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == filter_policy, timeout=4)

        # publish message that satisfies the filter policy, assert that message is received
        message_3 = f"message-{short_uid()}"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_3,
            MessageAttributes={"def": {"DataType": "Number", "StringValue": "99"}},
        )

        msgs_3 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )["Messages"]
        num_msgs_3 = len(msgs_3)
        # assert that it is not the the same message that #1
        assert json.loads(msgs_3[0]["Body"])["Message"] == message_3
        assert num_msgs_3 == num_msgs_1

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_4 = f"message-{short_uid()}"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_4,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )

        msgs_4 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )["Messages"]
        num_msgs_4 = len(msgs_4)
        # assert that it's still the same message that #3
        assert json.loads(msgs_4[0]["Body"])["Message"] == message_3
        assert num_msgs_4 == num_msgs_3

    @pytest.mark.aws_validated
    def test_subscribe_sqs_queue(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
    ):
        # TODO: check with non default external port

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        # create subscription with filter policy
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="FilterPolicy",
            AttributeValue=json.dumps(filter_policy),
        )

        # publish message that satisfies the filter policy
        message = "This is a test message"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )

        # assert that message is received
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            VisibilityTimeout=0,
            MessageAttributeNames=["All"],
            WaitTimeSeconds=4,
        )
        message = response["Messages"][0]
        message_body = json.loads(message["Body"])
        assert message_body["MessageAttributes"]["attr1"]["Value"] == "99.12"

    def test_subscribe_platform_endpoint(
        self, sns_client, sqs_create_queue, sns_create_topic, sns_subscription
    ):

        sns_backend = SNSBackend.get()
        topic_arn = sns_create_topic()["TopicArn"]

        app_arn = sns_client.create_platform_application(Name="app1", Platform="p1", Attributes={})[
            "PlatformApplicationArn"
        ]
        platform_arn = sns_client.create_platform_endpoint(
            PlatformApplicationArn=app_arn, Token="token_1"
        )["EndpointArn"]

        # create subscription with filter policy
        filter_policy = {"attr1": [{"numeric": [">", 0, "<=", 100]}]}
        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="application",
            Endpoint=platform_arn,
            Attributes={"FilterPolicy": json.dumps(filter_policy)},
        )
        # publish message that satisfies the filter policy
        message = "This is a test message"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "99.12"}},
        )

        # assert that message has been received
        def check_message():
            assert len(sns_backend.platform_endpoint_messages[platform_arn]) > 0

        retry(check_message, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

        # clean up
        sns_client.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])
        sns_client.delete_endpoint(EndpointArn=platform_arn)
        sns_client.delete_platform_application(PlatformApplicationArn=app_arn)

    def test_unknown_topic_publish(self, sns_client):
        fake_arn = "arn:aws:sns:us-east-1:123456789012:i_dont_exist"
        message = "This is a test message"

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fake_arn, Message=message)

        assert e.value.response["Error"]["Code"] == "NotFound"
        assert e.value.response["Error"]["Message"] == "Topic does not exist"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

    def test_publish_sms(self, sns_client):
        response = sns_client.publish(PhoneNumber="+33000000000", Message="This is a SMS")
        assert "MessageId" in response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_publish_non_existent_target(self, sns_client):
        with pytest.raises(ClientError) as ex:
            sns_client.publish(
                TargetArn="arn:aws:sns:us-east-1:000000000000:endpoint/APNS/abcdef/0f7d5971-aa8b-4bd5-b585-0826e9f93a66",
                Message="This is a push notification",
            )

        assert ex.value.response["Error"]["Code"] == "InvalidClientTokenId"

    def test_tags(self, sns_client, sns_create_topic):

        topic_arn = sns_create_topic()["TopicArn"]
        sns_client.tag_resource(
            ResourceArn=topic_arn,
            Tags=[
                {"Key": "123", "Value": "abc"},
                {"Key": "456", "Value": "def"},
                {"Key": "456", "Value": "def"},
            ],
        )

        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
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

        sns_client.untag_resource(ResourceArn=topic_arn, TagKeys=["123"])

        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
        assert len(tags["Tags"]) == 1
        assert tags["Tags"][0]["Key"] == "456"
        assert tags["Tags"][0]["Value"] == "def"

        sns_client.tag_resource(ResourceArn=topic_arn, Tags=[{"Key": "456", "Value": "pqr"}])

        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
        assert len(tags["Tags"]) == 1
        assert tags["Tags"][0]["Key"] == "456"
        assert tags["Tags"][0]["Value"] == "pqr"

    def test_topic_subscription(self, sns_client, sns_create_topic, sns_subscription):
        topic_arn = sns_create_topic()["TopicArn"]
        subscription = sns_subscription(
            TopicArn=topic_arn,
            Protocol="email",
            Endpoint="localstack@yopmail.com",
        )
        sns_backend = SNSBackend.get()

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_obj = sns_backend.subscription_status[subscription_arn]
            assert subscription_obj["Status"] == "Not Subscribed"

            _token = subscription_obj["Token"]
            sns_client.confirm_subscription(TopicArn=topic_arn, Token=_token)
            assert subscription_obj["Status"] == "Subscribed"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_sqs_topic_subscription_confirmation(
        self, sns_client, sns_create_topic, sqs_create_queue, sqs_queue_arn, sns_subscription
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_arn = sqs_queue_arn(sqs_create_queue())
        subscription = sns_subscription(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
        )

        def check_subscription():
            subscription_arn = subscription["SubscriptionArn"]
            subscription_attrs = sns_client.get_subscription_attributes(
                SubscriptionArn=subscription_arn
            )
            assert subscription_attrs["Attributes"]["PendingConfirmation"] == "false"

        retry(check_subscription, retries=PUBLICATION_RETRIES, sleep=PUBLICATION_TIMEOUT)

    def test_dead_letter_queue(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        create_lambda_function,
        sns_subscription,
    ):
        lambda_name = f"test-{short_uid()}"
        lambda_arn = aws_stack.lambda_function_arn(lambda_name)
        topic_arn = sns_create_topic()["TopicArn"]
        queue_name = f"test-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)

        create_lambda_function(
            func_name=lambda_name,
            handler_file=TEST_LAMBDA_PYTHON,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            DeadLetterConfig={"TargetArn": queue_arn},
        )
        sns_subscription(TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn)

        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }
        sns_client.publish(TopicArn=topic_arn, Message=json.dumps(payload))

        def receive_dlq():
            result = sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"], VisibilityTimeout=0
            )
            msg_attrs = result["Messages"][0]["MessageAttributes"]
            assert len(result["Messages"]) > 0
            assert "RequestID" in msg_attrs
            assert "ErrorCode" in msg_attrs
            assert "ErrorMessage" in msg_attrs

        retry(receive_dlq, retries=8, sleep=2)

    def test_redrive_policy_http_subscription(
        self,
        sns_client,
        sns_create_topic,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
        # self.unsubscribe_all_from_sns()
        dlq_name = f"dlq-{short_uid()}"
        dlq_url = sqs_create_queue(QueueName=dlq_name)
        dlq_arn = sqs_queue_arn(dlq_url)
        topic_arn = sns_create_topic()["TopicArn"]

        # create HTTP endpoint and connect it to SNS topic
        with HTTPServer() as server:
            server.expect_request("/subscription").respond_with_data(b"", 200)
            http_endpoint = server.url_for("/subscription")
            wait_for_port_open(server.port)

            subscription = sns_subscription(
                TopicArn=topic_arn, Protocol="http", Endpoint=http_endpoint
            )
            sns_client.set_subscription_attributes(
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

        wait_for_port_closed(server.port)

        sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"message": "test_redrive_policy"}),
        )

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = json.loads(response["Messages"][0]["Body"])
        assert message["Type"] == "Notification"
        assert json.loads(message["Message"])["message"] == "test_redrive_policy"

    def test_redrive_policy_lambda_subscription(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        create_lambda_function,
        sqs_client,
        sns_subscription,
    ):
        # self.unsubscribe_all_from_sns()
        dlq_name = f"dlq-{short_uid()}"
        dlq_url = sqs_create_queue(QueueName=dlq_name)
        dlq_arn = sqs_queue_arn(dlq_url)
        topic_arn = sns_create_topic()["TopicArn"]

        lambda_name = f"test-{short_uid()}"
        lambda_arn = create_lambda_function(
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )["CreateFunctionResponse"]["FunctionArn"]

        subscription = sns_subscription(TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn)

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )
        testutil.delete_lambda_function(lambda_name)

        sns_client.publish(
            TopicArn=topic_arn,
            Message=json.dumps({"message": "test_redrive_policy"}),
        )

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = json.loads(response["Messages"][0]["Body"])
        assert message["Type"] == "Notification"
        assert json.loads(message["Message"])["message"] == "test_redrive_policy"

    def test_redrive_policy_queue_subscription(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sqs_client,
        sns_subscription,
    ):
        # self.unsubscribe_all_from_sns()
        dlq_name = f"dlq-{short_uid()}"
        dlq_url = sqs_create_queue(QueueName=dlq_name)
        dlq_arn = sqs_queue_arn(dlq_url)

        topic_arn = sns_create_topic()["TopicArn"]
        invalid_queue_arn = aws_stack.sqs_queue_arn("invalid_queue")
        # subscribe with an invalid queue ARN, to trigger event on DLQ below
        subscription = sns_subscription(
            TopicArn=topic_arn, Protocol="sqs", Endpoint=invalid_queue_arn
        )

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )

        sns_client.publish(
            TopicArn=topic_arn, Message=json.dumps({"message": "test_redrive_policy"})
        )

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = json.loads(response["Messages"][0]["Body"])
        assert message["Type"] == "Notification"
        assert json.loads(message["Message"])["message"] == "test_redrive_policy"

    def test_publish_with_empty_subject(self, sns_client, sns_create_topic):
        topic_arn = sns_create_topic()["TopicArn"]

        # Publish without subject
        rs = sns_client.publish(TopicArn=topic_arn, Message=json.dumps({"message": "test_publish"}))
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject="",
                Message=json.dumps({"message": "test_publish"}),
            )

        assert e.value.response["Error"]["Code"] == "InvalidParameter"

    def test_create_topic_test_arn(self, sns_create_topic, sns_client):
        topic_name = f"topic-{short_uid()}"
        response = sns_create_topic(Name=topic_name)
        topic_arn_params = response["TopicArn"].split(":")
        testutil.response_arn_matches_partition(sns_client, response["TopicArn"])
        assert topic_arn_params[4] == get_aws_account_id()
        assert topic_arn_params[5] == topic_name

    def test_publish_message_by_target_arn(
        self, sns_client, sns_create_topic, create_lambda_function, sns_subscription
    ):
        # self.unsubscribe_all_from_sns()

        func_name = f"lambda-{short_uid()}"
        topic_arn = sns_create_topic()["TopicArn"]

        lambda_arn = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=func_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )["CreateFunctionResponse"]["FunctionArn"]
        subscription_arn = sns_subscription(
            TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn
        )["SubscriptionArn"]

        sns_client.publish(TopicArn=topic_arn, Message="test_message_1", Subject="test subject")

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

        sns_client.publish(TargetArn=topic_arn, Message="test_message_2", Subject="test subject")

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

    def test_publish_message_after_subscribe_topic(
        self,
        sns_client,
        sns_create_topic,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
        # self.unsubscribe_all_from_sns()

        topic_arn = sns_create_topic()["TopicArn"]

        queue_url = sqs_create_queue()
        queue_arn = sqs_queue_arn(queue_url)

        rs = sns_client.publish(
            TopicArn=topic_arn, Subject="test subject", Message="test_message_1"
        )
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        message_subject = "sqs subject"
        message_body = "test_message_2"

        rs = sns_client.publish(TopicArn=topic_arn, Subject=message_subject, Message=message_body)
        # time.sleep(100)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200
        message_id = rs["MessageId"]

        def get_message(q_url):
            resp = sqs_client.receive_message(QueueUrl=q_url, VisibilityTimeout=0)
            return json.loads(resp["Messages"][0]["Body"])

        message = retry(get_message, retries=3, sleep=2, q_url=queue_url)
        assert message["MessageId"] == message_id
        assert message["Subject"] == message_subject
        assert message["Message"] == message_body

    def test_create_duplicate_topic_with_more_tags(self, sns_client, sns_create_topic):
        topic_name = f"test-{short_uid()}"
        sns_create_topic(Name=topic_name)

        with pytest.raises(ClientError) as e:
            sns_client.create_topic(Name=topic_name, Tags=[{"Key": "456", "Value": "pqr"}])

        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["Error"]["Message"] == "Topic already exists with different tags"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    def test_create_duplicate_topic_check_idempotency(self, sns_create_topic):
        topic_name = f"test-{short_uid()}"
        tags = [{"Key": "a", "Value": "1"}, {"Key": "b", "Value": "2"}]
        kwargs = [
            {"Tags": tags},  # to create topic with two tags
            {"Tags": tags},  # to create the same topic again with same tags
            {"Tags": [tags[0]]},  # to create the same topic again with one of the tags from above
            {"Tags": []},  # to create the same topic again with no tags
        ]
        responses = []
        for arg in kwargs:
            responses.append(sns_create_topic(Name=topic_name, **arg))
        # assert TopicArn is returned by all the above create_topic calls
        for i in range(len(responses)):
            assert "TopicArn" in responses[i]

    @pytest.mark.skip(
        reason="Idempotency not supported in Moto backend. See bug https://github.com/spulec/moto/issues/2333"
    )
    def test_create_platform_endpoint_check_idempotency(self, sns_client):
        response = sns_client.create_platform_application(
            Name=f"test-{short_uid()}",
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
                sns_client.create_platform_endpoint(PlatformApplicationArn=platform_arn, **kwargs)
            )
        # Assert endpointarn is returned in every call create platform call
        for i in range(len(responses)):
            assert "EndpointArn" in responses[i]
        endpoint_arn = responses[0]["EndpointArn"]
        # clean up
        sns_client.delete_endpoint(EndpointArn=endpoint_arn)
        sns_client.delete_platform_application(PlatformApplicationArn=platform_arn)

    def test_publish_by_path_parameters(
        self,
        sns_create_topic,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
        topic_name = f"topic-{short_uid()}"
        queue_name = f"queue-{short_uid()}"

        message = f"test message {short_uid()}"
        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        base_url = config.get_edge_url()
        path = "Action=Publish&Version=2010-03-31&TopicArn={}&Message={}".format(topic_arn, message)

        queue_url = sqs_create_queue(QueueName=queue_name)
        queue_arn = sqs_queue_arn(queue_url)

        subscription_arn = sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)[
            "SubscriptionArn"
        ]

        r = requests.post(
            url="{}/?{}".format(base_url, path),
            headers=aws_stack.mock_aws_request_headers("sns"),
        )
        assert r.status_code == 200

        def get_notification(q_url):
            resp = sqs_client.receive_message(QueueUrl=q_url)
            return json.loads(resp["Messages"][0]["Body"])

        notification = retry(get_notification, retries=3, sleep=2, q_url=queue_url)
        assert notification["TopicArn"] == topic_arn
        assert notification["Message"] == message

        sns_client.unsubscribe(SubscriptionArn=subscription_arn)

    def test_multiple_subscriptions_http_endpoint(
        self, sns_client, sns_create_topic, sns_subscription
    ):
        # create a topic
        topic_arn = sns_create_topic()["TopicArn"]

        # build fake http server endpoints
        _requests = queue.Queue()

        # create HTTP endpoint and connect it to SNS topic
        def handler(request):
            _requests.put(request)
            return Response(status=429)

        number_of_endpoints = 4

        servers = []

        for _ in range(number_of_endpoints):
            server = HTTPServer()
            server.start()
            servers.append(server)
            server.expect_request("/").respond_with_handler(handler)
            http_endpoint = server.url_for("/")
            wait_for_port_open(http_endpoint)

            sns_subscription(TopicArn=topic_arn, Protocol="http", Endpoint=http_endpoint)

        # fetch subscription information
        subscription_list = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        assert subscription_list["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert (
            len(subscription_list["Subscriptions"]) == number_of_endpoints
        ), f"unexpected number of subscriptions {subscription_list}"

        for _ in range(number_of_endpoints):
            request = _requests.get(timeout=2)
            assert request.get_json(True)["TopicArn"] == topic_arn

        with pytest.raises(queue.Empty):
            # make sure only four requests are received
            _requests.get(timeout=1)

        for server in servers:
            server.stop()

    def test_publish_sms_endpoint(self, sns_client, sns_create_topic, sns_subscription):
        list_of_contacts = [
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
            f"+{random.randint(100000000, 9999999999)}",
        ]
        message = "Good news everyone!"
        topic_arn = sns_create_topic()["TopicArn"]
        for number in list_of_contacts:
            sns_subscription(TopicArn=topic_arn, Protocol="sms", Endpoint=number)

        sns_client.publish(Message=message, TopicArn=topic_arn)

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

    @pytest.mark.aws_validated
    def test_publish_sqs_from_sns(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        string_value = "99.12"
        sns_client.publish(
            TopicArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": string_value}},
        )

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        # format is of SQS MessageAttributes when RawDelivery is set to "true"
        assert response["Messages"][0]["MessageAttributes"] == {
            "attr1": {"DataType": "Number", "StringValue": string_value}
        }

        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response["Messages"][0]["ReceiptHandle"]
        )

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="false",
        )
        string_value = "100.12"
        sns_client.publish(
            TargetArn=topic_arn,
            Message="Test msg",
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": string_value}},
        )
        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        message_body = json.loads(response["Messages"][0]["Body"])
        # format is SNS MessageAttributes when RawDelivery is "false"
        assert message_body["MessageAttributes"] == {
            "attr1": {"Type": "Number", "Value": string_value}
        }

    @pytest.mark.aws_validated
    def test_publish_batch_messages_from_sns_to_sqs(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )

        publish_batch_response = sns_client.publish_batch(
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
            ],
        )
        assert "Successful" in publish_batch_response
        assert len(publish_batch_response["Successful"]) == 4
        assert "Failed" in publish_batch_response

        for successful_resp in publish_batch_response["Successful"]:
            assert "Id" in successful_resp
            assert "MessageId" in successful_resp

        message_received = set()

        def get_messages():
            response = sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"], WaitTimeSeconds=1
            )

            for message in response["Messages"]:
                message_received.add(message["MessageId"])
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

            assert len(message_received) == 4

        retry(get_messages, retries=3, sleep=1)

    def test_publish_batch_messages_from_fifo_topic_to_fifo_queue(
        self, sns_client, sns_create_topic, sqs_client, sqs_create_queue, sns_subscription
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(Name=topic_name, Attributes={"FifoTopic": "true"})["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        sns_subscription(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_url,
            Attributes={"RawMessageDelivery": "true"},
        )
        message_group_id = "complexMessageGroupId"
        publish_batch_response = sns_client.publish_batch(
            TopicArn=topic_arn,
            PublishBatchRequestEntries=[
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
            ],
        )

        assert "Successful" in publish_batch_response
        assert "Failed" in publish_batch_response

        for successful_resp in publish_batch_response["Successful"]:
            assert "Id" in successful_resp
            assert "MessageId" in successful_resp

        def get_messages(queue_url):
            response = sqs_client.receive_message(
                QueueUrl=queue_url,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
                MaxNumberOfMessages=10,
            )
            assert len(response["Messages"]) == 3
            for message in response["Messages"]:
                assert "Body" in message
                assert message["Attributes"]["MessageGroupId"] == message_group_id

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

    def test_publish_batch_exceptions(
        self, sns_client, sqs_client, sns_create_topic, sqs_create_queue, sns_subscription
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(Name=topic_name, Attributes={"FifoTopic": "true"})["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={"FifoQueue": "true"},
        )

        queue_arn = aws_stack.sqs_queue_arn(queue_url)

        sns_subscription(
            TopicArn=topic_arn,
            Protocol="sqs",
            Endpoint=queue_arn,
            Attributes={"RawMessageDelivery": "true"},
        )

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {
                        "Id": "1",
                        "Message": "Test Message with two attributes",
                    }
                ],
            )
        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": f"Id_{i}", "Message": f"message_{i}"} for i in range(11)
                ],
            )
        assert e.value.response["Error"]["Code"] == "TooManyEntriesInBatchRequest"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": "1", "Message": f"message_{i}"} for i in range(2)
                ],
            )
        assert e.value.response["Error"]["Code"] == "BatchEntryIdsNotDistinct"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    def add_xray_header(self, request, **kwargs):
        request.headers[
            "X-Amzn-Trace-Id"
        ] = "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"

    def test_publish_sqs_from_sns_with_xray_propagation(
        self, sns_client, sns_create_topic, sqs_client, sqs_create_queue, sns_subscription
    ):
        # TODO: remove or adapt for asf
        if SQS_BACKEND_IMPL != "elasticmq":
            pytest.skip("not using elasticmq as SQS backend")

        sns_client.meta.events.register("before-send.sns.Publish", self.add_xray_header)

        topic = sns_create_topic()
        topic_arn = topic["TopicArn"]
        queue_url = sqs_create_queue()

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_url)
        sns_client.publish(TargetArn=topic_arn, Message="X-Ray propagation test msg")

        response = sqs_client.receive_message(
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

    def test_create_topic_after_delete_with_new_tags(self, sns_create_topic, sns_client):
        topic_name = f"test-{short_uid()}"
        topic = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "pqr"}])
        sns_client.delete_topic(TopicArn=topic["TopicArn"])

        topic1 = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "abc"}])
        assert topic["TopicArn"] == topic1["TopicArn"]

    def test_not_found_error_on_get_subscription_attributes(
        self, sns_client, sns_create_topic, sqs_create_queue, sqs_queue_arn, sns_subscription
    ):

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        queue_arn = sqs_queue_arn(queue_url)

        subscription = sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        subscription_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"]
        )

        assert (
            subscription_attributes.get("Attributes").get("SubscriptionArn")
            == subscription["SubscriptionArn"]
        )

        sns_client.unsubscribe(SubscriptionArn=subscription["SubscriptionArn"])

        with pytest.raises(ClientError) as e:
            sns_client.get_subscription_attributes(SubscriptionArn=subscription["SubscriptionArn"])

        assert e.value.response["Error"]["Code"] == "NotFound"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 404

    def test_message_to_fifo_sqs(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(Name=topic_name, Attributes={"FifoTopic": "true"})["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        queue_arn = sqs_queue_arn(queue_url)

        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)

        message = "Test"
        sns_client.publish(TopicArn=topic_arn, Message=message, MessageGroupId=short_uid())

        def get_message():
            received = sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)[
                "Messages"
            ][0]["Body"]
            assert json.loads(received)["Message"] == message

        retry(get_message, retries=10, sleep_before=0.15, sleep=1)

    def test_validations_for_fifo(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
        topic_name = f"topic-{short_uid()}"
        fifo_topic_name = f"topic-{short_uid()}.fifo"
        fifo_queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(Name=topic_name)["TopicArn"]

        fifo_topic_arn = sns_create_topic(Name=fifo_topic_name, Attributes={"FifoTopic": "true"})[
            "TopicArn"
        ]

        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )

        fifo_queue_arn = sqs_queue_arn(fifo_queue_url)

        with pytest.raises(ClientError) as e:
            sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=fifo_queue_arn)

        assert e.match("standard SNS topic")

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fifo_topic_arn, Message="test")

        assert e.match("MessageGroupId")

    def test_empty_sns_message(
        self, sns_client, sqs_client, sns_topic, sqs_queue, sqs_queue_arn, sns_subscription
    ):
        topic_arn = sns_topic["Attributes"]["TopicArn"]
        queue_arn = sqs_queue_arn(sqs_queue)
        sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
        with pytest.raises(ClientError) as e:
            sns_client.publish(Message="", TopicArn=topic_arn)
        assert e.match("Empty message")
        assert (
            sqs_client.get_queue_attributes(
                QueueUrl=sqs_queue, AttributeNames=["ApproximateNumberOfMessages"]
            )["Attributes"]["ApproximateNumberOfMessages"]
            == "0"
        )

    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    @pytest.mark.aws_validated
    def test_dead_letter_queue_with_deleted_sqs_queue(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sqs_queue_exists,
        sns_create_sqs_subscription,
        sns_allow_topic_sqs_queue,
        raw_message_delivery,
        snapshot,
    ):
        snapshot.add_transformer(snapshot.transform.sqs_api())
        # Need to skip the MD5OfBody/Signature, because it contains a timestamp
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$.json_encoded_delivery..Body.Signature",
                "<signature>",
                reference_replacement=False,
            )
        )
        snapshot.add_transformer(
            snapshot.transform.jsonpath(
                "$.json_encoded_delivery..MD5OfBody", "<md5-hash>", reference_replacement=False
            )
        )

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        dlq_url = sqs_create_queue()
        dlq_arn = sqs_queue_arn(dlq_url)

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )

        if raw_message_delivery:
            sns_client.set_subscription_attributes(
                SubscriptionArn=subscription["SubscriptionArn"],
                AttributeName="RawMessageDelivery",
                AttributeValue="true",
            )

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url,
            sqs_queue_arn=dlq_arn,
            sns_topic_arn=topic_arn,
        )

        sqs_client.delete_queue(QueueUrl=queue_url)

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
        sns_client.publish(TopicArn=topic_arn, Message=message, MessageAttributes=message_attr)

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"

        if raw_message_delivery:
            assert response["Messages"][0]["Body"] == message
            # MessageAttributes are lost with RawDelivery in AWS
            assert "MessageAttributes" not in response["Messages"][0]
            snapshot.match("raw_message_delivery", response)
        else:
            received_message = json.loads(response["Messages"][0]["Body"])
            assert received_message["Type"] == "Notification"
            assert received_message["Message"] == message

            # Set the decoded JSON Body to be able to skip keys directly
            response["Messages"][0]["Body"] = received_message
            snapshot.match("json_encoded_delivery", response)

    @pytest.mark.aws_validated
    def test_message_attributes_not_missing(
        self,
        sns_client,
        sqs_client,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_create_queue,
    ):

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        assert subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )
        attributes = {
            "an-attribute-key": {"DataType": "String", "StringValue": "an-attribute-value"},
            "binary-attribute": {"DataType": "Binary", "BinaryValue": b"\x02\x03\x04"},
        }

        publish_response = sns_client.publish(
            TopicArn=topic_arn,
            Message="text",
            MessageAttributes=attributes,
        )
        assert publish_response["MessageId"]
        msg = sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        # as SNS piggybacks on SQS MessageAttributes when RawDelivery is true
        # BinaryValue depends on SQS implementation, and is decoded automatically
        assert msg["Messages"][0]["MessageAttributes"] == attributes
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=msg["Messages"][0]["ReceiptHandle"]
        )

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RawMessageDelivery",
            AttributeValue="false",
        )

        publish_response = sns_client.publish(
            TopicArn=topic_arn,
            Message="text",
            MessageAttributes=attributes,
        )
        assert publish_response["MessageId"]
        msg = sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        assert json.loads(msg["Messages"][0]["Body"])["MessageAttributes"] == {
            "an-attribute-key": {"Type": "String", "Value": "an-attribute-value"},
            "binary-attribute": {
                # binary payload in base64 encoded by AWS, UTF-8 for JSON
                # https://docs.aws.amazon.com/sns/latest/api/API_MessageAttributeValue.html
                # need to be decoded manually as it's part of the message Body
                "Type": "Binary",
                "Value": b64encode(b"\x02\x03\x04").decode("utf-8"),
            },
        }

    @pytest.mark.only_localstack
    @pytest.mark.aws_validated
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_subscribe_external_http_endpoint(
        self,
        sns_client,
        sns_create_http_endpoint,
        raw_message_delivery,
    ):
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
        assert payload["Type"] == "SubscriptionConfirmation"
        assert sub_request.headers["x-amz-sns-message-type"] == "SubscriptionConfirmation"
        assert "Signature" in payload
        assert "SigningCertURL" in payload

        token = payload["Token"]
        subscribe_url = payload["SubscribeURL"]
        service_url, subscribe_url_path = payload["SubscribeURL"].rsplit("/", maxsplit=1)
        assert subscribe_url == (
            f"{service_url}/?Action=ConfirmSubscription" f"&TopicArn={topic_arn}&Token={token}"
        )

        confirm_subscribe_request = requests.get(subscribe_url)
        confirm_subscribe = xmltodict.parse(confirm_subscribe_request.content)
        assert (
            confirm_subscribe["ConfirmSubscriptionResponse"]["ConfirmSubscriptionResult"][
                "SubscriptionArn"
            ]
            == subscription_arn
        )

        subscription_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        assert subscription_attributes["Attributes"]["PendingConfirmation"] == "false"

        message = "test_external_http_endpoint"
        sns_client.publish(TopicArn=topic_arn, Message=message)

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
        else:
            payload = notification_request.get_json(force=True)
            assert payload["Type"] == "Notification"
            assert "Signature" in payload
            assert "SigningCertURL" in payload
            assert payload["Message"] == message
            assert payload["UnsubscribeURL"] == expected_unsubscribe_url

        unsub_request = requests.get(expected_unsubscribe_url)
        unsubscribe_confirmation = xmltodict.parse(unsub_request.content)
        assert "UnsubscribeResponse" in unsubscribe_confirmation

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

    @pytest.mark.only_localstack
    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    def test_dlq_external_http_endpoint(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
        sns_create_http_endpoint,
        sns_create_sqs_subscription,
        sns_allow_topic_sqs_queue,
        raw_message_delivery,
    ):
        # Necessitate manual set up to allow external access to endpoint, only in local testing
        topic_arn, http_subscription_arn, endpoint_url, server = sns_create_http_endpoint(
            raw_message_delivery
        )

        dlq_url = sqs_create_queue()
        dlq_arn = sqs_queue_arn(dlq_url)

        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url, sqs_queue_arn=dlq_arn, sns_topic_arn=topic_arn
        )
        sns_client.set_subscription_attributes(
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

        subscription_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=http_subscription_arn
        )
        assert subscription_attributes["Attributes"]["PendingConfirmation"] == "false"

        server.stop()
        wait_for_port_closed(server.port)

        message = "test_dlq_external_http_endpoint"
        sns_client.publish(TopicArn=topic_arn, Message=message)

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=3)
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
        sqs_client.delete_message(QueueUrl=dlq_url, ReceiptHandle=receipt_handle)

        expected_unsubscribe_url = (
            f"{service_url}/?Action=Unsubscribe&SubscriptionArn={http_subscription_arn}"
        )

        unsub_request = requests.get(expected_unsubscribe_url)
        unsubscribe_confirmation = xmltodict.parse(unsub_request.content)
        assert "UnsubscribeResponse" in unsubscribe_confirmation

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=2)
        # AWS doesn't send to the DLQ if the UnsubscribeConfirmation fails to be delivered
        assert "Messages" not in response

    def test_publish_too_long_message(self, sns_client):
        fake_arn = "arn:aws:sns:us-east-1:123456789012:i_dont_exist"
        # simulate payload over 256kb
        message = "This is a test message" * 12000

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fake_arn, Message=message)

        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["Error"]["Message"] == "Message too long"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    def test_publish_to_gcm(self, sns_client):
        key = "mock_server_key"
        token = "mock_token"

        platform_app_arn = sns_client.create_platform_application(
            Name="firebase", Platform="GCM", Attributes={"PlatformCredential": key}
        )["PlatformApplicationArn"]

        endpoint_arn = sns_client.create_platform_endpoint(
            PlatformApplicationArn=platform_app_arn,
            Token=token,
        )["EndpointArn"]

        message = {
            "GCM": '{ "notification": {"title": "Title of notification", "body": "It works" } }'
        }

        with pytest.raises(ClientError) as ex:
            sns_client.publish(
                TargetArn=endpoint_arn, MessageStructure="json", Message=json.dumps(message)
            )

        assert ex.value.response["Error"]["Code"] == "InvalidParameter"

        sns_client.delete_endpoint(EndpointArn=endpoint_arn)
        sns_client.delete_platform_application(PlatformApplicationArn=platform_app_arn)
