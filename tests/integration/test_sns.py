# -*- coding: utf-8 -*-
import json
import queue
import random
from operator import itemgetter

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
from localstack.testing.aws.util import is_aws_cloud
from localstack.utils import testutil
from localstack.utils.net import wait_for_port_closed, wait_for_port_open
from localstack.utils.strings import short_uid
from localstack.utils.sync import poll_condition, retry
from localstack.utils.testutil import check_expected_lambda_log_events_length

from .awslambda.functions import lambda_integration
from .awslambda.test_lambda import (
    LAMBDA_RUNTIME_PYTHON37,
    TEST_LAMBDA_FUNCTION_PREFIX,
    TEST_LAMBDA_LIBS,
    TEST_LAMBDA_PYTHON,
    TEST_LAMBDA_PYTHON_ECHO,
)

PUBLICATION_TIMEOUT = 0.500
PUBLICATION_RETRIES = 4


@pytest.fixture(autouse=True)
def sns_snapshot_transformer(snapshot):
    snapshot.add_transformer(snapshot.transform.sns_api())


class TestSNSSubscription:
    @pytest.mark.aws_validated
    def test_python_lambda_subscribe_sns_topic(
        self,
        sns_client,
        sns_create_topic,
        sns_subscription,
        lambda_client,
        lambda_su_role,
        create_lambda_function,
        logs_client,
        snapshot,
    ):
        function_name = f"{TEST_LAMBDA_FUNCTION_PREFIX}-{short_uid()}"
        permission_id = f"test-statement-{short_uid()}"
        subject = "[Subject] Test subject"
        message = "Hello world."
        topic_arn = sns_create_topic()["TopicArn"]

        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            runtime=LAMBDA_RUNTIME_PYTHON37,
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
        snapshot.match("notification", notification)


class TestSNSProvider:
    @pytest.mark.aws_validated
    def test_publish_unicode_chars(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_client,
        sns_create_sqs_subscription,
        snapshot,
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

        snapshot.match("received-message", response)

    @pytest.mark.aws_validated
    def test_subscribe_with_invalid_protocol(
        self, sns_client, sns_create_topic, sns_subscription, snapshot
    ):
        topic_arn = sns_create_topic()["TopicArn"]

        with pytest.raises(ClientError) as e:
            sns_subscription(
                TopicArn=topic_arn, Protocol="test-protocol", Endpoint="localstack@yopmail.com"
            )

        snapshot.match("exception", e.value.response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
        ]
    )
    def test_attribute_raw_subscribe(
        self,
        sqs_client,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
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
        subscription_arn = subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )

        response_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes", response_attributes)

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
        snapshot.match("messages-response", response)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
            "$..Attributes.RawMessageDelivery",
        ]
    )
    def test_filter_policy(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
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

        response_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes", response_attributes)

        response_0 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=1
        )
        snapshot.match("messages-0", response_0)
        # get number of messages
        num_msgs_0 = len(response_0.get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message = "This is a test message"
        message_attributes = {"attr1": {"DataType": "Number", "StringValue": "99"}}
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes=message_attributes,
        )

        response_1 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-1", response_1)

        num_msgs_1 = len(response_1["Messages"])
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message = "This is another test message"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        response_2 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-2", response_2)
        num_msgs_2 = len(response_2["Messages"])
        assert num_msgs_2 == num_msgs_1

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
            "$..Attributes.RawMessageDelivery",  # todo: fix me (not added to response if false)
            "$..Attributes.sqs_queue_url",  # todo: fix me: added by moto? illegal?
        ]
    )
    def test_exists_filter_policy(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
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

        response_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-policy-1", response_attributes)

        response_0 = sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
        snapshot.match("messages-0", response_0)
        # get number of messages
        num_msgs_0 = len(response_0.get("Messages", []))

        # publish message that satisfies the filter policy, assert that message is received
        message_1 = "message-1"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_1,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )
        response_1 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-1", response_1)
        num_msgs_1 = len(response_1["Messages"])
        assert num_msgs_1 == (num_msgs_0 + 1)

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_2 = "message-2"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_2,
            MessageAttributes={"attr1": {"DataType": "Number", "StringValue": "111"}},
        )

        response_2 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-2", response_2)
        num_msgs_2 = len(response_2["Messages"])
        assert num_msgs_2 == num_msgs_1

        # delete first message
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=response_1["Messages"][0]["ReceiptHandle"]
        )

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
            return subscription_attrs["Attributes"]["FilterPolicy"]

        # wait for the new filter policy to be in effect
        poll_condition(lambda: get_filter_policy() == filter_policy, timeout=4)
        response_attributes_2 = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription_arn
        )
        snapshot.match("subscription-attributes-policy-2", response_attributes_2)

        # publish message that satisfies the filter policy, assert that message is received
        message_3 = "message-3"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_3,
            MessageAttributes={"def": {"DataType": "Number", "StringValue": "99"}},
        )

        response_3 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-3", response_3)
        num_msgs_3 = len(response_3["Messages"])
        assert num_msgs_3 == num_msgs_1

        # publish message that does not satisfy the filter policy, assert that message is not received
        message_4 = "message-4"
        sns_client.publish(
            TopicArn=topic_arn,
            Message=message_4,
            MessageAttributes={
                "store": {"DataType": "Number", "StringValue": "99"},
                "def": {"DataType": "Number", "StringValue": "99"},
            },
        )

        response_4 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=4
        )
        snapshot.match("messages-4", response_4)
        num_msgs_4 = len(response_4["Messages"])
        assert num_msgs_4 == num_msgs_3

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
            "$..Attributes.RawMessageDelivery",
        ]
    )
    def test_subscribe_sqs_queue(
        self,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_topic,
        sns_create_sqs_subscription,
        snapshot,
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

        response_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
        )
        snapshot.match("subscription-attributes", response_attributes)

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
        snapshot.match("messages", response)

    @pytest.mark.only_localstack
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

    @pytest.mark.aws_validated
    def test_unknown_topic_publish(self, sns_client, sns_create_topic, snapshot):
        # create topic to get the basic arn structure
        # otherwise you get InvalidClientTokenId exception because of account id
        topic_arn = sns_create_topic()["TopicArn"]
        # append to get an unknown topic
        fake_arn = f"{topic_arn}-fake"
        message = "This is a test message"

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fake_arn, Message=message)

        snapshot.match("error", e.value.response)

    @pytest.mark.only_localstack
    def test_publish_sms(self, sns_client):
        response = sns_client.publish(PhoneNumber="+33000000000", Message="This is a SMS")
        assert "MessageId" in response
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    @pytest.mark.only_localstack
    def test_publish_non_existent_target(self, sns_client):
        # todo: fix test, the client id in the ARN is wrong so can't test against AWS
        with pytest.raises(ClientError) as ex:
            sns_client.publish(
                TargetArn="arn:aws:sns:us-east-1:000000000000:endpoint/APNS/abcdef/0f7d5971-aa8b-4bd5-b585-0826e9f93a66",
                Message="This is a push notification",
            )

        assert ex.value.response["Error"]["Code"] == "InvalidClientTokenId"

    @pytest.mark.aws_validated
    def test_tags(self, sns_client, sns_create_topic, snapshot):

        topic_arn = sns_create_topic()["TopicArn"]
        with pytest.raises(ClientError) as exc:
            sns_client.tag_resource(
                ResourceArn=topic_arn,
                Tags=[
                    {"Key": "k1", "Value": "v1"},
                    {"Key": "k2", "Value": "v2"},
                    {"Key": "k2", "Value": "v2"},
                ],
            )
        snapshot.match("duplicate-key-error", exc.value.response)

        sns_client.tag_resource(
            ResourceArn=topic_arn,
            Tags=[
                {"Key": "k1", "Value": "v1"},
                {"Key": "k2", "Value": "v2"},
            ],
        )

        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
        # could not figure out the logic for tag order in AWS, so resorting to sorting it manually in place
        tags["Tags"].sort(key=itemgetter("Key"))
        snapshot.match("list-created-tags", tags)

        sns_client.untag_resource(ResourceArn=topic_arn, TagKeys=["k1"])
        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
        snapshot.match("list-after-delete-tags", tags)

        # test update tag
        sns_client.tag_resource(ResourceArn=topic_arn, Tags=[{"Key": "k2", "Value": "v2b"}])
        tags = sns_client.list_tags_for_resource(ResourceArn=topic_arn)
        snapshot.match("list-after-update-tags", tags)

    @pytest.mark.only_localstack
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

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Owner",
            "$..ConfirmationWasAuthenticated",
            "$..RawMessageDelivery",
        ]
    )
    def test_sqs_topic_subscription_confirmation(
        self, sns_client, sns_create_topic, sqs_create_queue, sns_create_sqs_subscription, snapshot
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        subscription_attrs = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        def check_subscription():
            nonlocal subscription_attrs
            if not subscription_attrs["PendingConfirmation"] == "false":
                subscription_arn = subscription_attrs["SubscriptionArn"]
                subscription_attrs = sns_client.get_subscription_attributes(
                    SubscriptionArn=subscription_arn
                )["Attributes"]
            else:
                snapshot.match("subscription-attrs", subscription_attrs)

            return subscription_attrs["PendingConfirmation"] == "false"

        # SQS subscriptions are auto confirmed if they are from the user and in the same region
        assert poll_condition(check_subscription, timeout=5)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.Message.raise_error",  # check lambda delivery format into DLQ
            "$..Messages..MessageAttributes.ErrorCode.Type",
            "$..Messages..MessageAttributes.ErrorMessage.Value",
        ]
    )
    @pytest.mark.xfail(
        reason="Behaviour and format diverges from AWS, see https://github.com/localstack/localstack/issues/6613"
    )
    def test_sns_topic_as_lambda_dead_letter_queue(
        self,
        sns_client,
        sqs_client,
        lambda_client,
        lambda_su_role,
        create_lambda_function,
        sns_create_topic,
        sqs_create_queue,
        sns_subscription,
        sns_create_sqs_subscription,
        snapshot,
    ):
        # todo check the skipped paths, as the format is very wrong
        snapshot.add_transformer(snapshot.transform.lambda_api())
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

        function_name = f"{TEST_LAMBDA_FUNCTION_PREFIX}-{short_uid()}"
        lambda_creation_response = create_lambda_function(
            func_name=function_name,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON37,
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
        lambda_client.add_permission(
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

        payload = {
            lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1,
        }
        sns_client.publish(TopicArn=lambda_topic_arn, Message=json.dumps(payload))

        def receive_dlq():
            result = sqs_client.receive_message(
                QueueUrl=queue_url, MessageAttributeNames=["All"], VisibilityTimeout=0
            )
            assert len(result["Messages"]) > 0
            return result

        # check that the SQS queue subscribed to the SNS topic used as DLQ received the error from the lambda
        # on AWS, event retries can be quite delayed, so we have to wait up to 6 minutes here
        # reduced retries when using localstack to avoid tests flaking
        retries = 120 if is_aws_cloud() else 3
        messages = retry(receive_dlq, retries=retries, sleep=3)

        messages["Messages"][0]["Body"] = json.loads(messages["Messages"][0]["Body"])
        messages["Messages"][0]["Body"]["Message"] = json.loads(
            messages["Messages"][0]["Body"]["Message"]
        )

        snapshot.match("messages", messages)

        # as we ignore some fields, still assert manually the presence of certain fields
        msg_body = messages["Messages"][0]["Body"]
        msg_attrs = msg_body["MessageAttributes"]
        assert "RequestID" in msg_attrs
        assert "ErrorCode" in msg_attrs
        assert "ErrorMessage" in msg_attrs

    @pytest.mark.only_localstack
    def test_redrive_policy_http_subscription(
        self,
        sns_client,
        sns_create_topic,
        sqs_client,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
    ):
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

    @pytest.mark.aws_validated  # snaphot ok
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Owner",
            "$..ConfirmationWasAuthenticated",
            "$..RawMessageDelivery",
        ]
    )
    def test_redrive_policy_lambda_subscription(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        lambda_client,
        create_lambda_function,
        lambda_su_role,
        sqs_client,
        sns_subscription,
        sns_allow_topic_sqs_queue,
        snapshot,
    ):
        dlq_url = sqs_create_queue()
        dlq_arn = sqs_queue_arn(dlq_url)
        topic_arn = sns_create_topic()["TopicArn"]
        sns_allow_topic_sqs_queue(
            sqs_queue_url=dlq_url, sqs_queue_arn=dlq_arn, sns_topic_arn=topic_arn
        )

        lambda_name = f"test-{short_uid()}"
        lambda_arn = create_lambda_function(
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON37,
            role=lambda_su_role,
        )["CreateFunctionResponse"]["FunctionArn"]

        subscription = sns_subscription(TopicArn=topic_arn, Protocol="lambda", Endpoint=lambda_arn)

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"],
            AttributeName="RedrivePolicy",
            AttributeValue=json.dumps({"deadLetterTargetArn": dlq_arn}),
        )
        response_attributes = sns_client.get_subscription_attributes(
            SubscriptionArn=subscription["SubscriptionArn"]
        )

        snapshot.match("subscription-attributes", response_attributes)

        lambda_client.delete_function(FunctionName=lambda_name)

        sns_client.publish(
            TopicArn=topic_arn,
            Message="test_redrive_policy",
        )

        response = sqs_client.receive_message(QueueUrl=dlq_url, WaitTimeSeconds=10)
        snapshot.match("messages", response)
        assert (
            len(response["Messages"]) == 1
        ), f"invalid number of messages in DLQ response {response}"
        message = json.loads(response["Messages"][0]["Body"])
        assert message["Type"] == "Notification"
        assert message["Message"] == "test_redrive_policy"

    @pytest.mark.aws_validated
    def test_publish_with_empty_subject(self, sns_client, sns_create_topic, snapshot):
        topic_arn = sns_create_topic()["TopicArn"]

        # Publish without subject
        rs = sns_client.publish(TopicArn=topic_arn, Message=json.dumps({"message": "test_publish"}))
        snapshot.match("response-without-subject", rs)
        assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

        with pytest.raises(ClientError) as e:
            sns_client.publish(
                TopicArn=topic_arn,
                Subject="",
                Message=json.dumps({"message": "test_publish"}),
            )

        snapshot.match("response-with-empty-subject", e.value.response)

    @pytest.mark.aws_validated
    def test_create_topic_test_arn(self, sns_create_topic, sns_client, snapshot):
        topic_name = "topic-test-create"
        response = sns_create_topic(Name=topic_name)
        snapshot.match("create-topic", response)
        topic_arn_params = response["TopicArn"].split(":")
        testutil.response_arn_matches_partition(sns_client, response["TopicArn"])
        # we match the response but need to be sure the resource name is the same
        assert topic_arn_params[5] == topic_name

        if not is_aws_cloud():
            assert topic_arn_params[4] == get_aws_account_id()

    @pytest.mark.aws_validated
    def test_publish_message_by_target_arn(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        # using an SQS subscription to test TopicArn/TargetArn as it is easier to check against AWS
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        sns_client.publish(TopicArn=topic_arn, Message="test-msg-1")

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )

        snapshot.match("receive-topic-arn", response)

        message = response["Messages"][0]
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])

        # publish with TargetArn instead of TopicArn
        sns_client.publish(TargetArn=topic_arn, Message="test-msg-2")

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            MessageAttributeNames=["All"],
            VisibilityTimeout=0,
            WaitTimeSeconds=4,
        )
        snapshot.match("receive-target-arn", response)

    @pytest.mark.aws_validated
    def test_publish_message_before_subscribe_topic(
        self,
        sns_client,
        sns_create_topic,
        sqs_client,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()

        rs = sns_client.publish(
            TopicArn=topic_arn, Subject="test-subject-before-sub", Message="test_message_before"
        )
        snapshot.match("publish-before-subscribing", rs)

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message_subject = "test-subject-after-sub"
        message_body = "test_message_after"

        rs = sns_client.publish(TopicArn=topic_arn, Subject=message_subject, Message=message_body)
        snapshot.match("publish-after-subscribing", rs)

        response = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5
        )
        # nothing was subscribing to the topic, so the first message is lost
        snapshot.match("receive-messages", response)

    @pytest.mark.aws_validated
    def test_create_duplicate_topic_with_more_tags(self, sns_client, sns_create_topic, snapshot):
        topic_name = "test-duplicated-topic-more-tags"
        sns_create_topic(Name=topic_name)

        with pytest.raises(ClientError) as e:
            sns_client.create_topic(Name=topic_name, Tags=[{"Key": "key1", "Value": "value1"}])

        snapshot.match("exception-duplicate", e.value.response)

    @pytest.mark.aws_validated
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

    @pytest.mark.only_localstack
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

    @pytest.mark.aws_validated
    def test_publish_by_path_parameters(
        self,
        sns_create_topic,
        sns_client,
        sqs_client,
        sqs_create_queue,
        sns_create_sqs_subscription,
        aws_http_client_factory,
        snapshot,
    ):
        message = "test message direct post request"
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        client = aws_http_client_factory("sns", region="us-east-1")

        if is_aws_cloud():
            endpoint_url = "https://sns.us-east-1.amazonaws.com"
        else:
            endpoint_url = config.get_edge_url()

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
        json_response["PublishResponse"]["ResponseMetadata"][
            "HTTPStatusCode"
        ] = response.status_code
        json_response["PublishResponse"]["ResponseMetadata"]["HTTPHeaders"] = dict(response.headers)
        snapshot.match("post-request", json_response)

        assert response.status_code == 200
        assert b"<PublishResponse" in response.content

        rs = sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0, WaitTimeSeconds=5)
        snapshot.match("messages", rs)
        msg_body = json.loads(rs["Messages"][0]["Body"])
        assert msg_body["TopicArn"] == topic_arn
        assert msg_body["Message"] == message

    @pytest.mark.only_localstack
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

    @pytest.mark.only_localstack
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
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
            "$..Attributes.sqs_queue_url",
        ]
    )
    def test_publish_sqs_from_sns(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
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
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)

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
        snapshot.match("message-raw-true", response)
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
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-false", response)

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
        snapshot.match("message-raw-false", response)
        message_body = json.loads(response["Messages"][0]["Body"])
        # format is SNS MessageAttributes when RawDelivery is "false"
        assert message_body["MessageAttributes"] == {
            "attr1": {"Type": "Number", "Value": string_value}
        }

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
        ]
    )
    def test_publish_batch_messages_from_sns_to_sqs(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
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
        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)

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
        snapshot.match("publish-batch", publish_batch_response)

        message_ids_received = set()
        messages = []

        def get_messages():
            # due to the random nature of receiving SQS messages, we need to consolidate a single object to match
            sqs_response = sqs_client.receive_message(
                QueueUrl=queue_url,
                WaitTimeSeconds=1,
                VisibilityTimeout=10,
                MessageAttributeNames=["All"],
                AttributeNames=["All"],
            )

            for message in sqs_response["Messages"]:
                if message["MessageId"] in message_ids_received:
                    continue

                message_ids_received.add(message["MessageId"])
                messages.append(message)

            assert len(messages) == 4

        retry(get_messages, retries=3, sleep=1)
        # we need to sort the list (the order does not matter as we're not using FIFO)
        messages.sort(key=itemgetter("Body"))
        snapshot.match("messages", {"Messages": messages})

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$.sub-attrs-raw-true.Attributes.Owner",
            "$.sub-attrs-raw-true.Attributes.ConfirmationWasAuthenticated",
            "$.topic-attrs.Attributes.DeliveryPolicy",
            "$.topic-attrs.Attributes.EffectiveDeliveryPolicy",
            "$.topic-attrs.Attributes.Policy.Statement..Action",  # SNS:Receive is added by moto but not returned in AWS
            "$..Messages..Attributes.SequenceNumber",
            "$..Successful..SequenceNumber",  # sequence number are not added
        ]
    )
    def test_publish_batch_messages_from_fifo_topic_to_fifo_queue(
        self,
        sns_client,
        sns_create_topic,
        sqs_client,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes={
                "FifoTopic": "true",
                "ContentBasedDeduplication": "true",
            },
        )["TopicArn"]

        response = sns_client.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic-attrs", response)

        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        subscription = sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)
        subscription_arn = subscription["SubscriptionArn"]

        sns_client.set_subscription_attributes(
            SubscriptionArn=subscription_arn,
            AttributeName="RawMessageDelivery",
            AttributeValue="true",
        )

        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        snapshot.match("sub-attrs-raw-true", response)

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
            sqs_response = sqs_client.receive_message(
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
                sqs_client.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"]
                )

            assert len(messages) == 3

        retry(get_messages, retries=5, sleep=1)
        snapshot.match("messages", {"Messages": messages})
        # todo add test for deduplication
        # https://docs.aws.amazon.com/cli/latest/reference/sns/publish-batch.html
        # https://docs.aws.amazon.com/sns/latest/dg/fifo-message-dedup.html
        # > The SQS FIFO queue consumer processes the message and deletes it from the queue before the visibility
        # > timeout expires.

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
        ]
    )
    def test_publish_batch_exceptions(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        fifo_topic_name = f"topic-{short_uid()}.fifo"
        topic_arn = sns_create_topic(Name=fifo_topic_name, Attributes={"FifoTopic": "true"})[
            "TopicArn"
        ]

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
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
            sns_client.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": f"Id_{i}", "Message": "Too many messages"} for i in range(11)
                ],
            )
        snapshot.match("too-many-msg", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
                TopicArn=topic_arn,
                PublishBatchRequestEntries=[
                    {"Id": "1", "Message": "Messages with the same ID"} for i in range(2)
                ],
            )
        snapshot.match("same-msg-id", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish_batch(
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

        # todo add test and implement behaviour for ContentBasedDeduplication or MessageDeduplicationId

    def test_publish_sqs_from_sns_with_xray_propagation(
        self, sns_client, sns_create_topic, sqs_client, sqs_create_queue, sns_subscription
    ):
        # TODO: remove or adapt for asf
        if SQS_BACKEND_IMPL != "elasticmq":
            pytest.skip("not using elasticmq as SQS backend")

        def add_xray_header(request, **kwargs):
            request.headers[
                "X-Amzn-Trace-Id"
            ] = "Root=1-3152b799-8954dae64eda91bc9a23a7e8;Parent=7fa8c0f79203be72;Sampled=1"

        sns_client.meta.events.register("before-send.sns.Publish", add_xray_header)

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

    @pytest.mark.aws_validated
    def test_create_topic_after_delete_with_new_tags(self, sns_create_topic, sns_client, snapshot):
        topic_name = f"test-{short_uid()}"
        topic = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "pqr"}])
        snapshot.match("topic-0", topic)
        sns_client.delete_topic(TopicArn=topic["TopicArn"])

        topic1 = sns_create_topic(Name=topic_name, Tags=[{"Key": "Name", "Value": "abc"}])
        snapshot.match("topic-1", topic1)

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Attributes.Owner",
            "$..Attributes.ConfirmationWasAuthenticated",
            "$..Attributes.RawMessageDelivery",
            "$..Subscriptions..Owner",
        ]
    )
    def test_not_found_error_on_set_subscription_attributes(
        self,
        sns_client,
        sns_create_topic,
        sqs_create_queue,
        sqs_queue_arn,
        sns_subscription,
        snapshot,
    ):

        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        queue_arn = sqs_queue_arn(queue_url)
        subscription = sns_subscription(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
        snapshot.match("sub", subscription)
        subscription_arn = subscription["SubscriptionArn"]

        response = sns_client.get_subscription_attributes(SubscriptionArn=subscription_arn)
        subscription_attributes = response["Attributes"]
        snapshot.match("sub-attrs", response)

        assert subscription_attributes["SubscriptionArn"] == subscription_arn

        subscriptions_by_topic = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        snapshot.match("subscriptions-for-topic-before-unsub", subscriptions_by_topic)
        assert len(subscriptions_by_topic["Subscriptions"]) == 1

        sns_client.unsubscribe(SubscriptionArn=subscription_arn)

        def check_subscription_deleted():
            try:
                # AWS doesn't give NotFound error on GetSubscriptionAttributes for a while, might be cached
                sns_client.set_subscription_attributes(
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
        subscriptions_by_topic = sns_client.list_subscriptions_by_topic(TopicArn=topic_arn)
        snapshot.match("subscriptions-for-topic-after-unsub", subscriptions_by_topic)
        assert len(subscriptions_by_topic["Subscriptions"]) == 0

    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Messages..Body.SignatureVersion",  # apparently, messages are not signed in fifo topics
            "$..Messages..Body.Signature",
            "$..Messages..Body.SigningCertURL",
            "$..Messages..Body.SequenceNumber",
            "$..Messages..Attributes.SequenceNumber",
        ]
    )
    def test_message_to_fifo_sqs(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        # it is the md5 hash of the body containing a timestamp
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "MessageDeduplicationId",
                value_replacement="<md5-hash>",
                reference_replacement=False,
            )
        )
        topic_name = f"topic-{short_uid()}.fifo"
        queue_name = f"queue-{short_uid()}.fifo"

        topic_arn = sns_create_topic(
            Name=topic_name,
            Attributes={
                "FifoTopic": "true",
                "ContentBasedDeduplication": "true",  # todo: not enforced yet
            },
        )["TopicArn"]
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )
        # todo check both ContentBasedDeduplication and MessageDeduplicationId when implemented
        # https://docs.aws.amazon.com/sns/latest/dg/fifo-message-dedup.html

        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        message = "Test"
        sns_client.publish(TopicArn=topic_arn, Message=message, MessageGroupId="message-group-id-1")

        response = sqs_client.receive_message(
            QueueUrl=queue_url,
            VisibilityTimeout=0,
            WaitTimeSeconds=10,
            AttributeNames=["All"],
        )
        snapshot.match("messages", response)

        msg_body = response["Messages"][0]["Body"]
        assert json.loads(msg_body)["Message"] == message

    @pytest.mark.aws_validated
    def test_validations_for_fifo(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
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

        with pytest.raises(ClientError) as e:
            sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=fifo_queue_url)

        assert e.match("standard SNS topic")
        snapshot.match("not-fifo-topic", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fifo_topic_arn, Message="test")

        assert e.match("MessageGroupId")
        snapshot.match("no-msg-group-id", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=fifo_topic_arn, Message="test", MessageGroupId=short_uid())
        # if ContentBasedDeduplication is not set at the topic level, it needs MessageDeduplicationId for each msg
        assert e.match("MessageDeduplicationId")
        assert e.match("ContentBasedDeduplication")
        snapshot.match("no-dedup-policy", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish(
                TopicArn=topic_arn, Message="test", MessageDeduplicationId=short_uid()
            )
        assert e.match("MessageDeduplicationId")
        snapshot.match("no-msg-dedup-regular-topic", e.value.response)

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=topic_arn, Message="test", MessageGroupId=short_uid())
        assert e.match("MessageGroupId")
        snapshot.match("no-msg-group-id-regular-topic", e.value.response)

    @pytest.mark.aws_validated
    def test_empty_sns_message(
        self,
        sns_client,
        sqs_client,
        sns_create_topic,
        sqs_create_queue,
        sns_create_sqs_subscription,
        snapshot,
    ):
        topic_arn = sns_create_topic()["TopicArn"]
        queue_url = sqs_create_queue()
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=queue_url)

        with pytest.raises(ClientError) as e:
            sns_client.publish(Message="", TopicArn=topic_arn)

        snapshot.match("empty-msg-error", e.value.response)

        queue_attrs = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        snapshot.match("queue-attrs", queue_attrs)

    @pytest.mark.parametrize("raw_message_delivery", [True, False])
    @pytest.mark.aws_validated
    def test_redrive_policy_sqs_queue_subscription(
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
        snapshot.match("messages", response)

    @pytest.mark.aws_validated
    def test_message_attributes_not_missing(
        self,
        sns_client,
        sqs_client,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_create_queue,
        snapshot,
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
        snapshot.match("publish-msg-raw", publish_response)

        msg = sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        # as SNS piggybacks on SQS MessageAttributes when RawDelivery is true
        # BinaryValue depends on SQS implementation, and is decoded automatically
        snapshot.match("raw-delivery-msg-attrs", msg)

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
        snapshot.match("publish-msg-json", publish_response)

        msg = sqs_client.receive_message(
            QueueUrl=queue_url,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
            WaitTimeSeconds=3,
        )
        snapshot.match("json-delivery-msg-attrs", msg)
        # binary payload in base64 encoded by AWS, UTF-8 for JSON
        # https://docs.aws.amazon.com/sns/latest/api/API_MessageAttributeValue.html

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

    @pytest.mark.aws_validated
    def test_publish_too_long_message(self, sns_client, sns_create_topic, snapshot):
        topic_arn = sns_create_topic()["TopicArn"]
        # simulate payload over 256kb
        message = "This is a test message" * 12000

        with pytest.raises(ClientError) as e:
            sns_client.publish(TopicArn=topic_arn, Message=message)

        snapshot.match("error", e.value.response)

        assert e.value.response["Error"]["Code"] == "InvalidParameter"
        assert e.value.response["Error"]["Message"] == "Invalid parameter: Message too long"
        assert e.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400

    @pytest.mark.only_localstack  # needs real credentials for GCM/FCM
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
