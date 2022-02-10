import datetime
import json
import os
import re
import time
from urllib.parse import urlencode

import pytest
import requests
from botocore.auth import SIGV4_TIMESTAMP, SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

from localstack import config, constants
from localstack.constants import TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_service_protocol, poll_condition, retry, short_uid, to_str

from .awslambda.functions import lambda_integration
from .awslambda.test_lambda import LAMBDA_RUNTIME_PYTHON36, TEST_LAMBDA_LIBS, TEST_LAMBDA_PYTHON
from .fixtures import only_localstack

TEST_QUEUE_NAME = "TestQueue"

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

TEST_LAMBDA_TAGS = {"tag1": "value1", "tag2": "value2", "tag3": ""}

TEST_MESSAGE_ATTRIBUTES = {
    "City": {
        "DataType": "String",
        "StringValue": "Any City - with special characters: <?`",
    },
    "Population": {"DataType": "Number", "StringValue": "1250800"},
}
TEST_REGION = "us-east-1"


class TestSqsProvider:
    @only_localstack
    def test_get_queue_url_contains_request_host(self, sqs_client, sqs_create_queue):
        if config.SERVICE_PROVIDER_CONFIG.get_provider("sqs") != "asf":
            pytest.xfail("this test only works for the ASF provider")

        queue_name = "test-queue-" + short_uid()

        sqs_create_queue(QueueName=queue_name)

        queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        account_id = constants.TEST_AWS_ACCOUNT_ID

        host = f"http://localhost:{config.EDGE_PORT}"
        # our current queue pattern looks like this, but may change going forward, or may be configurable
        assert queue_url == f"{host}/{account_id}/{queue_name}"

        # attempt to connect through a different host and make sure the URL contains that host
        host = f"http://127.0.0.1:{config.EDGE_PORT}"
        client = aws_stack.connect_to_service("sqs", endpoint_url=host)
        queue_url = client.get_queue_url(QueueName=queue_name)["QueueUrl"]
        assert queue_url == f"{host}/{account_id}/{queue_name}"

    def test_list_queues(self, sqs_client, sqs_create_queue):
        queue_names = [
            "a-test-queue-" + short_uid(),
            "a-test-queue-" + short_uid(),
            "b-test-queue-" + short_uid(),
        ]

        # create three queues with prefixes and collect their urls
        queue_urls = []
        for name in queue_names:
            sqs_create_queue(QueueName=name)
            queue_url = sqs_client.get_queue_url(QueueName=name)["QueueUrl"]
            assert queue_url.endswith(name)
            queue_urls.append(queue_url)

        # list queues with first prefix
        result = sqs_client.list_queues(QueueNamePrefix="a-test-queue-")
        assert "QueueUrls" in result
        assert len(result["QueueUrls"]) == 2
        assert queue_urls[0] in result["QueueUrls"]
        assert queue_urls[1] in result["QueueUrls"]
        assert queue_urls[2] not in result["QueueUrls"]

        # list queues with second prefix
        result = sqs_client.list_queues(QueueNamePrefix="b-test-queue-")
        assert "QueueUrls" in result
        assert len(result["QueueUrls"]) == 1
        assert queue_urls[0] not in result["QueueUrls"]
        assert queue_urls[1] not in result["QueueUrls"]
        assert queue_urls[2] in result["QueueUrls"]

        # list queues regardless of prefix prefix
        result = sqs_client.list_queues()
        assert "QueueUrls" in result
        for url in queue_urls:
            assert url in result["QueueUrls"]

    def test_create_queue_and_get_attributes(self, sqs_client, sqs_queue):
        result = sqs_client.get_queue_attributes(
            QueueUrl=sqs_queue, AttributeNames=["QueueArn", "CreatedTimestamp", "VisibilityTimeout"]
        )
        assert "Attributes" in result

        attrs = result["Attributes"]
        assert len(attrs) == 3
        assert "test-queue-" in attrs["QueueArn"]
        assert int(float(attrs["CreatedTimestamp"])) == pytest.approx(int(time.time()), 30)
        assert int(attrs["VisibilityTimeout"]) == 30, "visibility timeout is not the default value"

    def test_send_receive_message(self, sqs_client, sqs_queue):
        send_result = sqs_client.send_message(QueueUrl=sqs_queue, MessageBody="message")

        assert send_result["MessageId"]
        assert send_result["MD5OfMessageBody"] == "78e731027d8fd50ed642340b7c9a63b3"
        # TODO: other attributes

        receive_result = sqs_client.receive_message(QueueUrl=sqs_queue)

        assert len(receive_result["Messages"]) == 1
        message = receive_result["Messages"][0]

        assert message["ReceiptHandle"]
        assert message["Body"] == "message"
        assert message["MessageId"] == send_result["MessageId"]
        assert message["MD5OfBody"] == send_result["MD5OfMessageBody"]

    def test_send_receive_message_multiple_queues(self, sqs_client, sqs_create_queue):
        queue0 = sqs_create_queue()
        queue1 = sqs_create_queue()

        sqs_client.send_message(QueueUrl=queue0, MessageBody="message")

        result = sqs_client.receive_message(QueueUrl=queue1)
        assert "Messages" not in result

        result = sqs_client.receive_message(QueueUrl=queue0)
        assert len(result["Messages"]) == 1
        assert result["Messages"][0]["Body"] == "message"

    def test_send_message_batch(self, sqs_client, sqs_queue):
        sqs_client.send_message_batch(
            QueueUrl=sqs_queue,
            Entries=[
                {"Id": "1", "MessageBody": "message-0"},
                {"Id": "2", "MessageBody": "message-1"},
            ],
        )

        response0 = sqs_client.receive_message(QueueUrl=sqs_queue)
        response1 = sqs_client.receive_message(QueueUrl=sqs_queue)
        response2 = sqs_client.receive_message(QueueUrl=sqs_queue)

        assert len(response0.get("Messages", [])) == 1
        assert len(response1.get("Messages", [])) == 1
        assert len(response2.get("Messages", [])) == 0

        message0 = response0["Messages"][0]
        message1 = response1["Messages"][0]

        assert message0["Body"] == "message-0"
        assert message1["Body"] == "message-1"

    def test_send_batch_receive_multiple(self, sqs_client, sqs_queue):
        # send a batch, then a single message, then receive them
        # Important: AWS does not guarantee the order of messages, be it within the batch or between sends
        message_count = 3
        sqs_client.send_message_batch(
            QueueUrl=sqs_queue,
            Entries=[
                {"Id": "1", "MessageBody": "message-0"},
                {"Id": "2", "MessageBody": "message-1"},
            ],
        )
        sqs_client.send_message(QueueUrl=sqs_queue, MessageBody="message-2")
        i = 0
        result_recv = {"Messages": []}
        while len(result_recv["Messages"]) < message_count and i < message_count:
            result_recv["Messages"] = result_recv["Messages"] + (
                sqs_client.receive_message(
                    QueueUrl=sqs_queue, MaxNumberOfMessages=message_count
                ).get("Messages")
            )
            i += 1
        assert len(result_recv["Messages"]) == message_count
        assert set(result_recv["Messages"][b]["Body"] for b in range(message_count)) == set(
            f"message-{b}" for b in range(message_count)
        )

    def test_send_message_batch_with_empty_list(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        try:
            sqs_client.send_message_batch(QueueUrl=queue_url, Entries=[])
        except ClientError as e:
            assert "EmptyBatchRequest" in e.response["Error"]["Code"]
            assert e.response["ResponseMetadata"]["HTTPStatusCode"] in [400, 404]

    def test_tag_untag_queue(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2", "tag3": ""}
        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)

        # check queue tags
        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

        # remove tag1 and tag3
        sqs_client.untag_queue(QueueUrl=queue_url, TagKeys=["tag1", "tag3"])
        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag2": "value2"}

        # remove tag2
        sqs_client.untag_queue(QueueUrl=queue_url, TagKeys=["tag2"])

        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert "Tags" not in response

    def test_tags_case_sensitive(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"MyTag": "value1", "mytag": "value2"}
        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)

        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

    def test_untag_queue_ignores_non_existing_tag(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2"}
        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)

        # remove tags
        sqs_client.untag_queue(QueueUrl=queue_url, TagKeys=["tag1", "tag3"])

        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag2": "value2"}

    def test_tag_queue_overwrites_existing_tag(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        # tag queue
        tags = {"tag1": "value1", "tag2": "value2"}
        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)

        # overwrite tags
        tags = {"tag1": "VALUE1", "tag3": "value3"}
        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)

        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == {"tag1": "VALUE1", "tag2": "value2", "tag3": "value3"}

    def test_create_queue_with_tags(self, sqs_client, sqs_create_queue):
        tags = {"tag1": "value1", "tag2": "value2"}
        queue_url = sqs_create_queue(tags=tags)

        response = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert response["Tags"] == tags

    def test_create_queue_with_attributes(self, sqs_client, sqs_create_queue):
        attributes = {
            "MessageRetentionPeriod": "604800",  # Unsupported by ElasticMq, should be saved in memory
            "ReceiveMessageWaitTimeSeconds": "10",
            "VisibilityTimeout": "20",
        }

        queue_url = sqs_create_queue(Attributes=attributes)

        attrs = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
            "Attributes"
        ]

        assert attrs["MessageRetentionPeriod"] == "604800"
        assert attrs["VisibilityTimeout"] == "20"
        assert attrs["ReceiveMessageWaitTimeSeconds"] == "10"

    def test_send_delay_and_wait_time(self, sqs_client, sqs_queue):
        sqs_client.send_message(QueueUrl=sqs_queue, MessageBody="foobar", DelaySeconds=1)

        result = sqs_client.receive_message(QueueUrl=sqs_queue)
        assert "Messages" not in result

        result = sqs_client.receive_message(QueueUrl=sqs_queue, WaitTimeSeconds=2)
        assert "Messages" in result
        assert len(result["Messages"]) == 1

    def test_receive_after_visibility_timeout(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue(Attributes={"VisibilityTimeout": "1"})

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="foobar")

        # receive the message
        result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" in result
        message_receipt_0 = result["Messages"][0]

        # message should be within the visibility timeout
        result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result

        # visibility timeout should have expired
        result = sqs_client.receive_message(QueueUrl=queue_url, WaitTimeSeconds=2)
        assert "Messages" in result
        message_receipt_1 = result["Messages"][0]

        assert (
            message_receipt_0["ReceiptHandle"] != message_receipt_1["ReceiptHandle"]
        ), "receipt handles should be different"

    def test_receive_terminate_visibility_timeout(self, sqs_client, sqs_queue):
        queue_url = sqs_queue

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="foobar")

        result = sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=0)
        assert "Messages" in result
        message_receipt_0 = result["Messages"][0]

        result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" in result
        message_receipt_1 = result["Messages"][0]

        assert (
            message_receipt_0["ReceiptHandle"] != message_receipt_1["ReceiptHandle"]
        ), "receipt handles should be different"

        # TODO: check if this is correct (whether receive with VisibilityTimeout = 0 is permanent)
        result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result

    def test_delete_message_batch_from_lambda(
        self, sqs_client, sqs_create_queue, lambda_client, create_lambda_function
    ):
        # issue 3671 - not recreatable
        # TODO: lambda creation does not work when testing against AWS
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        lambda_name = f"lambda-{short_uid()}"
        create_lambda_function(
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        delete_batch_payload = {lambda_integration.MSG_BODY_DELETE_BATCH: queue_url}
        batch = []
        for i in range(4):
            batch.append({"Id": str(i), "MessageBody": str(i)})
        sqs_client.send_message_batch(QueueUrl=queue_url, Entries=batch)

        lambda_client.invoke(
            FunctionName=lambda_name, Payload=json.dumps(delete_batch_payload), LogType="Tail"
        )

        receive_result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in receive_result.keys()

    def test_invalid_receipt_handle_should_return_error_message(self, sqs_client, sqs_create_queue):
        # issue 3619
        queue_name = "queue_3619_" + short_uid()
        queue_url = sqs_create_queue(QueueName=queue_name)
        with pytest.raises(Exception) as e:
            sqs_client.change_message_visibility(
                QueueUrl=queue_url, ReceiptHandle="INVALID", VisibilityTimeout=60
            )
        e.match("ReceiptHandleIsInvalid")

    def test_message_with_attributes_should_be_enqueued(self, sqs_client, sqs_create_queue):
        # issue 3737
        queue_name = "queue_3737_" + short_uid()
        queue_url = sqs_create_queue(QueueName=queue_name)
        assert queue_url.endswith(queue_name)

        message_body = "test"
        timestamp_attribute = {"DataType": "Number", "StringValue": "1614717034367"}
        message_attributes = {"timestamp": timestamp_attribute}
        response_send = sqs_client.send_message(
            QueueUrl=queue_url, MessageBody=message_body, MessageAttributes=message_attributes
        )
        response_receive = sqs_client.receive_message(QueueUrl=queue_url)
        assert response_receive["Messages"][0]["MessageId"] == response_send["MessageId"]

    @pytest.mark.xfail
    def test_batch_send_with_invalid_char_should_succeed(self, sqs_client, sqs_create_queue):
        # issue 4135
        queue_name = "queue_4135_" + short_uid()
        queue_url = sqs_create_queue(QueueName=queue_name)

        batch = []
        for i in range(0, 9):
            batch.append({"Id": str(i), "MessageBody": str(i)})
        batch.append({"Id": "9", "MessageBody": "\x01"})
        result_send = sqs_client.send_message_batch(QueueUrl=queue_url, Entries=batch)
        assert len(result_send["Failed"]) == 1

    @only_localstack
    def test_external_hostname(self, monkeypatch, sqs_client, sqs_create_queue):
        external_host = "external-host"
        external_port = "12345"

        monkeypatch.setattr(config, "SQS_PORT_EXTERNAL", external_port)
        monkeypatch.setattr(config, "HOSTNAME_EXTERNAL", external_host)
        # TODO: remove once the old provider is discontinued
        from localstack.services.sqs import sqs_listener as old_sqs_listener

        monkeypatch.setattr(old_sqs_listener, "SQS_PORT_EXTERNAL", external_port)

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        assert f"{external_host}:{external_port}" in queue_url

        message_body = "external_host_test"
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_body)

        receive_result = sqs_client.receive_message(QueueUrl=queue_url)
        assert receive_result["Messages"][0]["Body"] == message_body

    @only_localstack
    def test_external_hostname_via_host_header(self, sqs_create_queue):
        """test making a request with a different external hostname/port being returned"""
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

    @only_localstack
    @pytest.mark.xfail
    def test_external_host_via_header_complete_message_lifecycle(self, monkeypatch):
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

        queue_url = f"http://{url}/{constants.TEST_AWS_ACCOUNT_ID}/{queue_name}"
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
        queue_url = f"http://127.0.0.1/{constants.TEST_AWS_ACCOUNT_ID}/{queue_name}"

        payload = f"Action=SendMessage&QueueUrl={queue_url}&MessageBody={message_body}"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert "MD5" in result.text

        queue_url = f"http://127.0.0.1/{constants.TEST_AWS_ACCOUNT_ID}/{queue_name}"

        payload = f"Action=ReceiveMessage&QueueUrl={queue_url}&VisibilityTimeout=0"
        result = requests.post(edge_url, data=payload, headers=headers)
        assert result.status_code == 200
        assert message_body in result.text

    @pytest.mark.xfail
    def test_fifo_messages_in_order_after_timeout(self, sqs_client, sqs_create_queue):
        # issue 4287
        queue_name = f"queue-{short_uid()}.fifo"
        timeout = 1
        attributes = {"FifoQueue": "true", "VisibilityTimeout": f"{timeout}"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        for i in range(3):
            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=f"message-{i}",
                MessageGroupId="1",
                MessageDeduplicationId=f"{i}",
            )

        def receive_and_check_order():
            result_receive = sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10)
            for j in range(3):
                assert result_receive["Messages"][j]["Body"] == f"message-{j}"

        receive_and_check_order()
        time.sleep(timeout + 1)
        receive_and_check_order()

    def test_list_queue_tags(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        tags = {"testTag1": "test1", "testTag2": "test2"}

        sqs_client.tag_queue(QueueUrl=queue_url, Tags=tags)
        tag_list = sqs_client.list_queue_tags(QueueUrl=queue_url)
        assert tags == tag_list["Tags"]

    def test_queue_list_nonexistent_tags(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        tag_list = sqs_client.list_queue_tags(QueueUrl=queue_url)

        assert "Tags" not in tag_list["ResponseMetadata"].keys()

    def test_publish_get_delete_message(self, sqs_client, sqs_create_queue):

        # visibility part handled by test_receive_terminate_visibility_timeout
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_body = "test message"
        result_send = sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_body)

        result_recv = sqs_client.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == result_send["MessageId"]

        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_recv["Messages"][0]["ReceiptHandle"]
        )
        result_recv = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result_recv.keys()

    def test_delete_message_deletes_with_change_visibility_timeout(
        self, sqs_client, sqs_create_queue
    ):
        # Old name: test_delete_message_deletes_visibility_agnostic
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        message_id = sqs_client.send_message(QueueUrl=queue_url, MessageBody="test")["MessageId"]
        result_recv = sqs_client.receive_message(QueueUrl=queue_url)
        result_follow_up = sqs_client.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id
        assert "Messages" not in result_follow_up.keys()

        receipt_handle = result_recv["Messages"][0]["ReceiptHandle"]
        sqs_client.change_message_visibility(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle, VisibilityTimeout=0
        )

        # check if the new timeout enables instant re-receiving, to ensure the message was deleted
        result_recv = sqs_client.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id

        receipt_handle = result_recv["Messages"][0]["ReceiptHandle"]
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)
        result_follow_up = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in result_follow_up.keys()

    def test_publish_get_delete_message_batch(self, sqs_client, sqs_create_queue):
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

        result_send_batch = sqs_client.send_message_batch(QueueUrl=queue_url, Entries=message_batch)
        successful = result_send_batch["Successful"]
        assert len(successful) == len(message_batch)

        result_recv = []
        i = 0
        while len(result_recv) < message_count and i < message_count:
            result_recv.extend(
                sqs_client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=message_count)[
                    "Messages"
                ]
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
        sqs_client.delete_message_batch(QueueUrl=queue_url, Entries=delete_entries)
        confirmation = sqs_client.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=message_count
        )
        assert "Messages" not in confirmation.keys()

    def test_create_and_send_to_fifo_queue(self, sqs_client, sqs_create_queue):
        # Old name: test_create_fifo_queue
        queue_name = f"queue-{short_uid()}.fifo"
        attributes = {"FifoQueue": "true"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        # it should preserve .fifo in the queue name
        assert queue_name in queue_url

        message_id = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody="test",
            MessageDeduplicationId=f"dedup-{short_uid()}",
            MessageGroupId="test_group",
        )["MessageId"]

        result_recv = sqs_client.receive_message(QueueUrl=queue_url)
        assert result_recv["Messages"][0]["MessageId"] == message_id

    def test_fifo_queue_requires_suffix(self, sqs_create_queue):
        queue_name = f"invalid-{short_uid()}"
        attributes = {"FifoQueue": "true"}

        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name, Attributes=attributes)
        e.match("InvalidParameterValue")

    @pytest.mark.skipif(
        os.environ.get("PROVIDER_OVERRIDE_SQS") != "asf",
        reason="New provider test which isn't covered by old one",
    )
    def test_standard_queue_cannot_have_fifo_suffix(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}.fifo"
        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name)
        e.match("InvalidParameterValue")

    @pytest.mark.xfail
    def test_redrive_policy_attribute_validity(self, sqs_create_queue, sqs_client):
        dl_queue_name = f"dl-queue-{short_uid()}"
        dl_queue_url = sqs_create_queue(QueueName=dl_queue_name)
        dl_target_arn = sqs_client.get_queue_attributes(
            QueueUrl=dl_queue_url, AttributeNames=["QueueArn"]
        )["Attributes"]["QueueArn"]
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        valid_max_receive_count = "42"
        invalid_max_receive_count = "invalid"

        with pytest.raises(Exception) as e:
            sqs_client.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={"RedrivePolicy": json.dumps({"deadLetterTargetArn": dl_target_arn})},
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            sqs_client.set_queue_attributes(
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
            sqs_client.set_queue_attributes(
                QueueUrl=queue_url,
                Attributes={"RedrivePolicy": json.dumps(_invalid_redrive_policy)},
            )
        e.match("InvalidParameterValue")

        _valid_redrive_policy = {
            "deadLetterTargetArn": dl_target_arn,
            "maxReceiveCount": valid_max_receive_count,
        }

        sqs_client.set_queue_attributes(
            QueueUrl=queue_url, Attributes={"RedrivePolicy": json.dumps(_valid_redrive_policy)}
        )

    @pytest.mark.skip
    def test_invalid_dead_letter_arn_rejected_before_lookup(self, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        dl_dummy_arn = "dummy"
        max_receive_count = 42
        _redrive_policy = {
            "deadLetterTargetArn": dl_dummy_arn,
            "maxReceiveCount": max_receive_count,
        }
        with pytest.raises(Exception) as e:
            sqs_create_queue(
                QueueName=queue_name, Attributes={"RedrivePolicy": json.dumps(_redrive_policy)}
            )
        e.match("InvalidParameterValue")

    def test_set_queue_policy(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"Policy": TEST_POLICY}
        sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        # accessing the policy generally and specifically
        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
            "Attributes"
        ]
        policy = json.loads(attributes["Policy"])
        assert "sqs:SendMessage" == policy["Statement"][0]["Action"]
        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])[
            "Attributes"
        ]
        policy = json.loads(attributes["Policy"])
        assert "sqs:SendMessage" == policy["Statement"][0]["Action"]

    def test_set_empty_queue_policy(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"Policy": ""}
        sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)

        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
            "Attributes"
        ]
        assert "Policy" not in attributes.keys()

        # check if this behaviour holds on existing Policies as well
        attributes = {"Policy": TEST_POLICY}
        sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
            "Attributes"
        ]
        assert "sqs:SendMessage" in attributes["Policy"]

        attributes = {"Policy": ""}
        sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        attributes = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])[
            "Attributes"
        ]
        assert "Policy" not in attributes.keys()

    def test_send_message_with_attributes(self, sqs_client, sqs_create_queue):
        # Old name: test_send_message_attributes
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {
            "attr1": {"StringValue": "test1", "DataType": "String"},
            "attr2": {"StringValue": "test2", "DataType": "String"},
        }
        result_send = sqs_client.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=attributes
        )

        result_receive = sqs_client.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        messages = result_receive["Messages"]

        assert messages[0]["MessageId"] == result_send["MessageId"]
        assert messages[0]["MessageAttributes"] == attributes
        assert messages[0]["MD5OfMessageAttributes"] == result_send["MD5OfMessageAttributes"]

    def test_sent_message_retains_attributes_after_receive(self, sqs_client, sqs_create_queue):
        # Old name: test_send_message_retains_attributes
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        attributes = {"attr1": {"StringValue": "test1", "DataType": "String"}}
        sqs_client.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=attributes
        )

        # receive should not interfere with message attributes
        sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, MessageAttributeNames=["All"]
        )
        receive_result = sqs_client.receive_message(
            QueueUrl=queue_url, MessageAttributeNames=["All"]
        )
        assert receive_result["Messages"][0]["MessageAttributes"] == attributes

    @pytest.mark.xfail
    def test_send_message_with_invalid_string_attributes(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        # base line against to detect general failure
        valid_attribute = {"attr.1øßä": {"StringValue": "Valida", "DataType": "String"}}
        sqs_client.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=valid_attribute
        )

        def send_invalid(attribute):
            with pytest.raises(Exception) as e:
                sqs_client.send_message(
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

        too_long_type = f"Number.{'L'*256}"
        invalid_attribute = {
            "Attribute_name": {"StringValue": "Valid", "DataType": f"{too_long_type}"}
        }
        send_invalid(invalid_attribute)

        ends_with_dot = "Invalid."
        invalid_attribute = {f"{ends_with_dot}": {"StringValue": "Valid", "DataType": "String"}}
        send_invalid(invalid_attribute)

    @pytest.mark.xfail
    def test_send_message_with_invalid_fifo_parameters(self, sqs_client, sqs_create_queue):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(
            QueueName=fifo_queue_name,
            Attributes={"FifoQueue": "true"},
        )
        with pytest.raises(Exception) as e:
            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody="test",
                MessageDeduplicationId=f"Invalid-{chr(8)}",
                MessageGroupId="1",
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody="test",
                MessageDeduplicationId="1",
                MessageGroupId=f"Invalid-{chr(8)}",
            )
        e.match("InvalidParameterValue")

    def test_send_message_with_invalid_payload_characters(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        invalid_message_body = f"Invalid-{chr(0)}-{chr(8)}-{chr(19)}-{chr(65535)}"

        with pytest.raises(Exception) as e:
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=invalid_message_body)
        e.match("InvalidMessageContents")

    def test_dead_letter_queue_config(self, sqs_client, sqs_create_queue):

        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dead_letter_queue-{short_uid()}"

        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)
        url_parts = dl_queue_url.split("/")
        region = get_region()
        dl_target_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )

        conf = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 50}
        attributes = {"RedrivePolicy": json.dumps(conf)}

        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=attributes)

        assert queue_url

    def test_dead_letter_queue_execution(
        self, sqs_client, sqs_create_queue, lambda_client, create_lambda_function
    ):

        # TODO: lambda creation does not work when testing against AWS
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dl-queue-{short_uid()}"
        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)

        # create arn
        url_parts = dl_queue_url.split("/")
        region = os.environ.get("AWS_DEFAULT_REGION") or TEST_REGION
        dl_target_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )

        policy = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 1}
        queue_url = sqs_create_queue(
            QueueName=queue_name, Attributes={"RedrivePolicy": json.dumps(policy)}
        )

        lambda_name = f"lambda-{short_uid()}"
        create_lambda_function(
            func_name=lambda_name,
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        # create arn
        url_parts = queue_url.split("/")
        queue_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )
        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn, FunctionName=lambda_name
        )

        # add message to SQS, which will trigger the Lambda, resulting in an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload))

        assert poll_condition(
            lambda: "Messages"
            in sqs_client.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0),
            10.0,
            1.0,
        )
        result_recv = sqs_client.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0)
        assert result_recv["Messages"][0]["Body"] == json.dumps(payload)

    def test_dead_letter_queue_max_receive_count(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dl-queue-{short_uid()}"
        dl_queue_url = sqs_create_queue(
            QueueName=dead_letter_queue_name, Attributes={"VisibilityTimeout": "0"}
        )

        # create arn
        url_parts = dl_queue_url.split("/")
        dl_target_arn = aws_stack.sqs_queue_arn(
            url_parts[-1], account_id=url_parts[len(url_parts) - 2]
        )

        policy = {"deadLetterTargetArn": dl_target_arn, "maxReceiveCount": 1}
        queue_url = sqs_create_queue(
            QueueName=queue_name,
            Attributes={"RedrivePolicy": json.dumps(policy), "VisibilityTimeout": "0"},
        )
        result_send = sqs_client.send_message(QueueUrl=queue_url, MessageBody="test")

        result_recv1_messages = sqs_client.receive_message(QueueUrl=queue_url).get("Messages")
        result_recv2_messages = sqs_client.receive_message(QueueUrl=queue_url).get("Messages")
        # only one request received a message
        assert (result_recv1_messages is None) != (result_recv2_messages is None)

        assert poll_condition(
            lambda: "Messages" in sqs_client.receive_message(QueueUrl=dl_queue_url), 5.0, 1.0
        )
        assert (
            sqs_client.receive_message(QueueUrl=dl_queue_url)["Messages"][0]["MessageId"]
            == result_send["MessageId"]
        )

    @pytest.mark.skipif(
        os.environ.get("PROVIDER_OVERRIDE_SQS") != "asf", reason="Currently fails for moto provider"
    )
    def test_dead_letter_queue_chain(self, sqs_client, sqs_create_queue):
        # test a chain of 3 queues, with DLQ flow q1 -> q2 -> q3

        # create queues
        queue_names = [f"q-{short_uid()}", f"q-{short_uid()}", f"q-{short_uid()}"]
        for queue_name in queue_names:
            sqs_create_queue(QueueName=queue_name, Attributes={"VisibilityTimeout": "0"})
        queue_urls = [aws_stack.get_sqs_queue_url(queue_name) for queue_name in queue_names]

        # set redrive policies
        for idx, queue_name in enumerate(queue_names[:2]):
            policy = {
                "deadLetterTargetArn": aws_stack.sqs_queue_arn(queue_names[idx + 1]),
                "maxReceiveCount": 1,
            }
            sqs_client.set_queue_attributes(
                QueueUrl=queue_urls[idx],
                Attributes={"RedrivePolicy": json.dumps(policy), "VisibilityTimeout": "0"},
            )

        def _retry_receive(q_url):
            def _receive():
                _result = sqs_client.receive_message(QueueUrl=q_url)
                assert _result.get("Messages")
                return _result

            return retry(_receive, sleep=1, retries=5)

        # send message
        result = sqs_client.send_message(QueueUrl=queue_urls[0], MessageBody="test")
        # retrieve message from q1
        result = _retry_receive(queue_urls[0])
        assert len(result.get("Messages")) == 1
        # Wait for VisibilityTimeout to expire
        time.sleep(1.1)
        # retrieve message from q1 again -> no message, should go to DLQ q2
        result = sqs_client.receive_message(QueueUrl=queue_urls[0])
        assert not result.get("Messages")
        # retrieve message from q2
        result = _retry_receive(queue_urls[1])
        assert len(result.get("Messages")) == 1
        # retrieve message from q2 again -> no message, should go to DLQ q3
        result = sqs_client.receive_message(QueueUrl=queue_urls[1])
        assert not result.get("Messages")
        # retrieve message from q3
        result = _retry_receive(queue_urls[2])
        assert len(result.get("Messages")) == 1

    # TODO: check if test_set_queue_attribute_at_creation == test_create_queue_with_attributes

    def test_get_specific_queue_attribute_response(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = f"dead_letter_queue-{short_uid()}"

        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)
        region = get_region()
        dl_result = sqs_client.get_queue_attributes(
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
        get_two_attributes = sqs_client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["MessageRetentionPeriod", "RedrivePolicy"],
        )
        get_single_attribute = sqs_client.get_queue_attributes(
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
    def test_set_unsupported_attribute_fifo(self, sqs_client, sqs_create_queue):
        # TODO: behaviour diverges from AWS
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        with pytest.raises(Exception) as e:
            sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes={"FifoQueue": "true"})
        e.match("InvalidAttributeName")

        fifo_queue_name = f"queue-{short_uid()}.fifo"
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )
        sqs_client.set_queue_attributes(QueueUrl=fifo_queue_url, Attributes={"FifoQueue": "true"})
        with pytest.raises(Exception) as e:
            sqs_client.set_queue_attributes(
                QueueUrl=fifo_queue_url, Attributes={"FifoQueue": "false"}
            )
        e.match("InvalidAttributeValue")

    def test_fifo_queue_send_multiple_messages_multiple_single_receives(
        self, sqs_client, sqs_create_queue
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
            result = sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=f"message{i}",
                MessageDeduplicationId=f"deduplication{i}",
                MessageGroupId=group_id,
            )
            sent_messages.append(result)

        for i in range(message_count):
            result = sqs_client.receive_message(QueueUrl=queue_url)
            message = result["Messages"][0]
            assert message["Body"] == f"message{i}"
            assert message["MD5OfBody"] == sent_messages[i]["MD5OfMessageBody"]
            assert message["MessageId"] == sent_messages[i]["MessageId"]
            sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])

    @pytest.mark.xfail
    def test_disallow_queue_name_with_slashes(self, sqs_client, sqs_create_queue):
        queue_name = f"queue/{short_uid()}/"
        with pytest.raises(Exception) as e:
            sqs_create_queue(QueueName=queue_name)
        e.match("InvalidParameterValue")

    def test_post_list_queues_with_auth_in_presigned_url(self):
        # TODO: does not work when testing against AWS
        method = "post"
        protocol = get_service_protocol()
        # CI might not set EDGE_PORT variables properly
        port = 4566
        if protocol == "https":
            port = 443
        base_url = "{}://{}:{}".format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, port)

        req = AWSRequest(
            method=method,
            url=base_url,
            data={"Action": "ListQueues", "Version": "2012-11-05"},
        )

        # boto doesn't support querystring-style auth, so we have to do some
        # weird logic to use boto's signing functions, to understand what's
        # going on here look at the internals of the SigV4Auth.add_auth
        # method.
        datetime_now = datetime.datetime.utcnow()
        req.context["timestamp"] = datetime_now.strftime(SIGV4_TIMESTAMP)
        signer = SigV4Auth(
            Credentials(TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY),
            "sqs",
            os.environ.get("AWS_DEFAULT_REGION") or TEST_REGION,
        )
        canonical_request = signer.canonical_request(req)
        string_to_sign = signer.string_to_sign(req, canonical_request)

        payload = {
            "Action": "ListQueues",
            "Version": "2012-11-05",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": signer.scope(req),
            "X-Amz-SignedHeaders": ";".join(signer.headers_to_sign(req).keys()),
            "X-Amz-Signature": signer.signature(string_to_sign, req),
        }

        response = requests.post(url=base_url, data=urlencode(payload))
        assert response.status_code == 200
        assert b"<ListQueuesResponse" in response.content

    # FIXME: make this testcase work against the new provider
    @pytest.mark.xfail
    def test_get_list_queues_with_auth_in_presigned_url(self):
        # TODO: does not work when testing against AWS
        method = "get"
        protocol = get_service_protocol()
        port = config.EDGE_PORT_HTTP
        if protocol == "https":
            port = config.EDGE_PORT
        base_url = "{}://{}:{}".format(get_service_protocol(), config.LOCALSTACK_HOSTNAME, port)

        req = AWSRequest(
            method=method,
            url=base_url,
            data={"Action": "ListQueues", "Version": "2012-11-05"},
        )

        # boto doesn't support querystring-style auth, so we have to do some
        # weird logic to use boto's signing functions, to understand what's
        # going on here look at the internals of the SigV4Auth.add_auth
        # method.
        datetime_now = datetime.datetime.utcnow()
        req.context["timestamp"] = datetime_now.strftime(SIGV4_TIMESTAMP)
        signer = SigV4Auth(
            Credentials(TEST_AWS_ACCESS_KEY_ID, TEST_AWS_SECRET_ACCESS_KEY),
            "sqs",
            os.environ.get("AWS_DEFAULT_REGION") or TEST_REGION,
        )
        canonical_request = signer.canonical_request(req)
        string_to_sign = signer.string_to_sign(req, canonical_request)

        payload = {
            "Action": "ListQueues",
            "Version": "2012-11-05",
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": signer.scope(req),
            "X-Amz-SignedHeaders": ";".join(signer.headers_to_sign(req).keys()),
            "X-Amz-Signature": signer.signature(string_to_sign, req),
        }

        response = requests.get(base_url, params=payload)
        assert response.status_code == 200
        assert b"<ListQueuesResponse" in response.content

    @pytest.mark.xfail
    def test_system_attributes_have_no_effect_on_attr_md5(self, sqs_create_queue, sqs_client):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        msg_attrs_provider = {"timestamp": {"StringValue": "1493147359900", "DataType": "Number"}}
        aws_trace_header = {
            "AWSTraceHeader": {
                "StringValue": "Root=1-5759e988-bd862e3fe1be46a994272793;Parent=53995c3f42cd8ad8;Sampled=1",
                "DataType": "String",
            }
        }
        response_send = sqs_client.send_message(
            QueueUrl=queue_url, MessageBody="test", MessageAttributes=msg_attrs_provider
        )
        response_send_system_attr = sqs_client.send_message(
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

    def test_inflight_message_requeue(self, sqs_client, sqs_create_queue):
        visibility_timeout = 3 if os.environ.get("TEST_TARGET") == "AWS_CLOUD" else 2
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(
            QueueName=queue_name
        )  # , Attributes={"VisibilityTimeout": str(visibility_timeout)})
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="test1")
        result_receive1 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=visibility_timeout
        )
        time.sleep(visibility_timeout / 2)
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="test2")
        time.sleep(visibility_timeout)
        result_receive2 = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=visibility_timeout
        )

        assert result_receive1["Messages"][0]["Body"] == result_receive2["Messages"][0]["Body"]

    @pytest.mark.xfail
    def test_sequence_number(self, sqs_client, sqs_create_queue):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        fifo_queue_url = sqs_create_queue(
            QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"}
        )
        message_content = f"test{short_uid()}"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"

        send_result_fifo = sqs_client.send_message(
            QueueUrl=fifo_queue_url,
            MessageBody=message_content,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        assert "SequenceNumber" in send_result_fifo.keys()

        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        send_result = sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_content)
        assert "SequenceNumber" not in send_result

    # Tests of diverging behaviour that was discovered during rewrite
    @pytest.mark.xfail
    def test_posting_to_fifo_requires_deduplicationid_group_id(self, sqs_client, sqs_create_queue):
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"})
        message_content = f"test{short_uid()}"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"

        with pytest.raises(Exception) as e:
            sqs_client.send_message(
                QueueUrl=queue_url, MessageBody=message_content, MessageGroupId=group_id
            )
        e.match("InvalidParameterValue")

        with pytest.raises(Exception) as e:
            sqs_client.send_message(
                QueueUrl=queue_url, MessageBody=message_content, MessageDeduplicationId=dedup_id
            )
        e.match("MissingParameter")

    # TODO: test approximateNumberOfMessages once delayed Messages are properly counted
    def test_approximate_number_of_messages_delayed(self):
        pass

    @pytest.mark.xfail
    def test_posting_to_queue_via_queue_name(self, sqs_client, sqs_create_queue):
        # TODO: behaviour diverges from AWS
        queue_name = f"queue-{short_uid()}"
        sqs_create_queue(QueueName=queue_name)

        result_send = sqs_client.send_message(
            QueueUrl=queue_name, MessageBody="Using name instead of URL"
        )
        assert result_send["MD5OfMessageBody"] == "86a83f96652a1bfad3891e7d523750cb"
        assert result_send["ResponseMetadata"]["HTTPStatusCode"] == 200

    @pytest.mark.xfail
    def test_invalid_string_attributes_cause_invalid_parameter_value_error(
        self, sqs_client, sqs_create_queue
    ):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        invalid_attribute = {
            "attr1": {"StringValue": f"Invalid-{chr(8)},{chr(11)}", "DataType": "String"}
        }

        with pytest.raises(Exception) as e:
            sqs_client.send_message(
                QueueUrl=queue_url, MessageBody="test", MessageAttributes=invalid_attribute
            )
        e.match("InvalidParameterValue")

    def test_change_message_visibility_not_permanent(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="test")
        result_receive = sqs_client.receive_message(QueueUrl=queue_url)
        receipt_handle = result_receive.get("Messages")[0]["ReceiptHandle"]
        sqs_client.change_message_visibility(
            QueueUrl=queue_url, ReceiptHandle=receipt_handle, VisibilityTimeout=0
        )
        result_recv_1 = sqs_client.receive_message(QueueUrl=queue_url)
        result_recv_2 = sqs_client.receive_message(QueueUrl=queue_url)
        assert (
            result_recv_1.get("Messages")[0]["MessageId"]
            == result_receive.get("Messages")[0]["MessageId"]
        )
        assert "Messages" not in result_recv_2.keys()

    @pytest.mark.skip
    def test_dead_letter_queue_execution_lambda_mapping_preserves_id(
        self, sqs_client, sqs_create_queue, lambda_client, create_lambda_function
    ):
        # TODO: lambda triggered dead letter delivery does not preserve the message id
        # https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
        queue_name = f"queue-{short_uid()}"
        dead_letter_queue_name = "dl-queue-{}".format(short_uid())
        dl_queue_url = sqs_create_queue(QueueName=dead_letter_queue_name)

        # create arn
        url_parts = dl_queue_url.split("/")
        region = get_region()
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
            libs=TEST_LAMBDA_LIBS,
            handler_file=TEST_LAMBDA_PYTHON,
            runtime=LAMBDA_RUNTIME_PYTHON36,
        )
        # create arn
        url_parts = queue_url.split("/")
        queue_arn = "arn:aws:sqs:{}:{}:{}".format(
            region, url_parts[len(url_parts) - 2], url_parts[-1]
        )
        lambda_client.create_event_source_mapping(
            EventSourceArn=queue_arn, FunctionName=lambda_name
        )

        # add message to SQS, which will trigger the Lambda, resulting in an error
        payload = {lambda_integration.MSG_BODY_RAISE_ERROR_FLAG: 1}
        result_send = sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(payload))

        assert poll_condition(
            lambda: "Messages"
            in sqs_client.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0),
            5.0,
            1.0,
        )
        result_recv = sqs_client.receive_message(QueueUrl=dl_queue_url, VisibilityTimeout=0)
        assert result_recv["Messages"][0]["MessageId"] == result_send["MessageId"]

    # verification of community posted issue
    # FIXME: \r gets lost
    @pytest.mark.skip
    def test_message_with_carriage_return(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        message_content = "{\r\n" + '"machineID" : "d357006e26ff47439e1ef894225d4307"' + "}"
        result_send = sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_content)
        result_receive = sqs_client.receive_message(QueueUrl=queue_url)
        assert result_send["MD5OfMessageBody"] == result_receive["Messages"][0]["MD5OfBody"]
        assert message_content == result_receive["Messages"][0]["Body"]

    def test_purge_queue(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        for i in range(3):
            message_content = f"test-{i}"
            sqs_client.send_message(QueueUrl=queue_url, MessageBody=message_content)
        approx_nr_of_messages = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        assert int(approx_nr_of_messages["Attributes"]["ApproximateNumberOfMessages"]) > 1
        sqs_client.purge_queue(QueueUrl=queue_url)
        receive_result = sqs_client.receive_message(QueueUrl=queue_url)
        assert "Messages" not in receive_result.keys()

    def test_remove_message_with_old_receipt_handle(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="test")
        result_receive = sqs_client.receive_message(QueueUrl=queue_url, VisibilityTimeout=1)
        time.sleep(2)
        receipt_handle = result_receive["Messages"][0]["ReceiptHandle"]
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt_handle)

        # This is more suited to the check than receiving because it simply
        # returns the number of elements in the queue, without further logic
        approx_nr_of_messages = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
        )
        assert int(approx_nr_of_messages["Attributes"]["ApproximateNumberOfMessages"]) == 0

    @pytest.mark.skip(
        reason="this is an AWS behaviour test that requires 5 minutes to run. Only execute manually"
    )
    def test_deduplication_interval(self, sqs_client, sqs_create_queue):
        # TODO: AWS behaviour here "seems" inconsistent -> current code might need adaption
        fifo_queue_name = f"queue-{short_uid()}.fifo"
        queue_url = sqs_create_queue(QueueName=fifo_queue_name, Attributes={"FifoQueue": "true"})
        message_content = f"test{short_uid()}"
        message_content_duplicate = f"{message_content}-duplicate"
        message_content_half_time = f"{message_content}-half_time"
        dedup_id = f"fifo_dedup-{short_uid()}"
        group_id = f"fifo_group-{short_uid()}"
        result_send = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        time.sleep(3)
        sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_duplicate,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        result_receive = sqs_client.receive_message(QueueUrl=queue_url)
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_receive["Messages"][0]["ReceiptHandle"]
        )
        result_receive_duplicate = sqs_client.receive_message(QueueUrl=queue_url)

        assert result_send.get("MessageId") == result_receive.get("Messages")[0].get("MessageId")
        assert result_send.get("MD5OfMessageBody") == result_receive.get("Messages")[0].get(
            "MD5OfBody"
        )
        assert "Messages" not in result_receive_duplicate.keys()

        result_send = sqs_client.send_message(
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
        sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_half_time,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        time.sleep(6 * 60)

        result_send_duplicate = sqs_client.send_message(
            QueueUrl=queue_url,
            MessageBody=message_content_duplicate,
            MessageGroupId=group_id,
            MessageDeduplicationId=dedup_id,
        )
        result_receive = sqs_client.receive_message(QueueUrl=queue_url)
        sqs_client.delete_message(
            QueueUrl=queue_url, ReceiptHandle=result_receive["Messages"][0]["ReceiptHandle"]
        )
        result_receive_duplicate = sqs_client.receive_message(QueueUrl=queue_url)

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

    @pytest.mark.skipif(
        os.environ.get("PROVIDER_OVERRIDE_SQS") != "asf",
        reason="New provider test which isn't covered by old one",
    )
    def test_sse_attributes_are_accepted(self, sqs_client, sqs_create_queue):
        queue_name = f"queue-{short_uid()}"
        queue_url = sqs_create_queue(QueueName=queue_name)
        attributes = {
            "KmsMasterKeyId": "testKeyId",
            "KmsDataKeyReusePeriodSeconds": "6000",
            "SqsManagedSseEnabled": "true",
        }
        sqs_client.set_queue_attributes(QueueUrl=queue_url, Attributes=attributes)
        result_attributes = sqs_client.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["All"]
        )["Attributes"]
        keys = result_attributes.keys()
        for k in attributes.keys():
            assert k in keys
            assert attributes[k] == result_attributes[k]


def get_region():
    return os.environ.get("AWS_DEFAULT_REGION") or TEST_REGION


# TODO: test visibility timeout (with various ways to set them: queue attributes, receive parameter, update call)
# TODO: test message attributes and message system attributes


class TestSqsLambdaIntegration:
    pass
    # TODO: move tests here
