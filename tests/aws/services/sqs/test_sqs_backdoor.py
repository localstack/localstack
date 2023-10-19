import pytest
import requests
import xmltodict
from botocore.exceptions import ClientError

from localstack.services.sqs.utils import parse_queue_url
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


def _parse_message_attributes(xml) -> list[dict]:
    """
    Takes an XML document returned by a SQS ``ReceiveMessage`` call and returns a dictionary of the
    message attributes for each message.
    """
    d = xmltodict.parse(xml)

    return [
        {attr["Name"]: attr["Value"] for attr in msg["Attribute"]}
        for msg in d["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
    ]


def _parse_attribute_map(json_message: dict) -> dict[str, str]:
    return {attr["Name"]: attr["Value"] for attr in json_message["Attribute"]}


class TestSqsDeveloperEdpoints:
    @markers.aws.only_localstack
    def test_list_messages_has_no_side_effects(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

        # check that accessing messages for this queue URL does not affect `ApproximateReceiveCount`
        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages", params={"QueueUrl": queue_url}
        )
        attributes = _parse_message_attributes(response.text)
        assert attributes[0]["ApproximateReceiveCount"] == "0"
        assert attributes[1]["ApproximateReceiveCount"] == "0"

        # do a real receive op that has a side effect
        response = aws_client.sqs.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, MaxNumberOfMessages=1, AttributeNames=["All"]
        )
        assert response["Messages"][0]["Body"] == "message-1"
        assert response["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "1"

        # check backdoor access again
        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages", params={"QueueUrl": queue_url}
        )
        attributes = _parse_message_attributes(response.text)
        assert attributes[0]["ApproximateReceiveCount"] == "1"
        assert attributes[1]["ApproximateReceiveCount"] == "0"

    @markers.aws.only_localstack
    def test_list_messages_as_botocore_endpoint_url(
        self, sqs_create_queue, aws_client, aws_client_factory
    ):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

        # use the developer endpoint as boto client URL
        client = aws_client_factory(endpoint_url="http://localhost:4566/_aws/sqs/messages").sqs
        # max messages is ignored
        response = client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

        assert len(response["Messages"]) == 2

        assert response["Messages"][0]["Body"] == "message-1"
        assert response["Messages"][1]["Body"] == "message-2"
        assert response["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "0"
        assert response["Messages"][1]["Attributes"]["ApproximateReceiveCount"] == "0"

    @markers.aws.only_localstack
    def test_fifo_list_messages_as_botocore_endpoint_url(
        self, sqs_create_queue, aws_client, aws_client_factory
    ):
        queue_url = sqs_create_queue(
            QueueName=f"queue-{short_uid()}.fifo",
            Attributes={
                "FifoQueue": "true",
                "ContentBasedDeduplication": "true",
            },
        )

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2", MessageGroupId="1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-3", MessageGroupId="2")

        # use the developer endpoint as boto client URL
        client = aws_client_factory(endpoint_url="http://localhost:4566/_aws/sqs/messages").sqs
        # max messages is ignored
        response = client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

        assert len(response["Messages"]) == 3

        assert response["Messages"][0]["Body"] == "message-1"
        assert response["Messages"][1]["Body"] == "message-2"
        assert response["Messages"][2]["Body"] == "message-3"
        assert response["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "0"
        assert response["Messages"][1]["Attributes"]["ApproximateReceiveCount"] == "0"
        assert response["Messages"][2]["Attributes"]["ApproximateReceiveCount"] == "0"
        assert response["Messages"][0]["Attributes"]["MessageGroupId"] == "1"
        assert response["Messages"][1]["Attributes"]["MessageGroupId"] == "1"
        assert response["Messages"][2]["Attributes"]["MessageGroupId"] == "2"

    @markers.aws.only_localstack
    def test_list_messages_with_invalid_action_raises_error(
        self, sqs_create_queue, aws_client_factory
    ):
        queue_url = sqs_create_queue()

        client = aws_client_factory(endpoint_url="http://localhost:4566/_aws/sqs/messages").sqs

        with pytest.raises(ClientError) as e:
            client.send_message(QueueUrl=queue_url, MessageBody="foobar")

        assert e.value.response["Error"]["Code"] == "InvalidRequest"
        assert (
            e.value.response["Error"]["Message"]
            == "This endpoint only accepts ReceiveMessage calls"
        )

    @markers.aws.only_localstack
    def test_list_messages_as_json(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": queue_url},
            headers={"Accept": "application/json"},
        )
        doc = response.json()

        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]

        assert len(messages) == 2
        assert messages[0]["Body"] == "message-1"
        assert messages[0]["MD5OfBody"] == "3d6b824fd8c1520e9a047d21fee6fb1f"

        assert messages[1]["Body"] == "message-2"
        assert messages[1]["MD5OfBody"] == "95ef155b66299d14edf7ed57c468c13b"

        # make sure attributes are returned
        attributes = {a["Name"]: a["Value"] for a in messages[0]["Attribute"]}
        assert attributes["SenderId"] == "000000000000"
        assert "ApproximateReceiveCount" in attributes
        assert "ApproximateFirstReceiveTimestamp" in attributes
        assert "SentTimestamp" in attributes

    @markers.aws.only_localstack
    def test_list_messages_with_invisible_messages(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-3")

        # check out a messages
        aws_client.sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": queue_url, "ShowInvisible": False},
            headers={"Accept": "application/json"},
        )
        doc = response.json()
        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
        assert len(messages) == 2
        assert messages[0]["Body"] == "message-2"
        assert messages[1]["Body"] == "message-3"

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": queue_url, "ShowInvisible": True},
            headers={"Accept": "application/json"},
        )
        doc = response.json()
        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
        assert len(messages) == 3
        assert messages[0]["Body"] == "message-1"
        assert messages[1]["Body"] == "message-2"
        assert messages[2]["Body"] == "message-3"

        assert _parse_attribute_map(messages[0])["IsVisible"] == "false"
        assert _parse_attribute_map(messages[1])["IsVisible"] == "true"
        assert _parse_attribute_map(messages[2])["IsVisible"] == "true"

    @markers.aws.only_localstack
    def test_list_messages_with_delayed_messages(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2", DelaySeconds=10)
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-3", DelaySeconds=10)

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": queue_url, "ShowDelayed": False},
            headers={"Accept": "application/json"},
        )
        doc = response.json()
        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
        assert messages["Body"] == "message-1"

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": queue_url, "ShowDelayed": True},
            headers={"Accept": "application/json"},
        )
        doc = response.json()
        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
        assert len(messages) == 3
        messages.sort(key=lambda k: k["Body"])
        assert messages[0]["Body"] == "message-1"
        assert messages[1]["Body"] == "message-2"
        assert messages[2]["Body"] == "message-3"

        assert _parse_attribute_map(messages[0])["IsDelayed"] == "false"
        assert _parse_attribute_map(messages[1])["IsDelayed"] == "true"
        assert _parse_attribute_map(messages[2])["IsDelayed"] == "true"

    @markers.aws.only_localstack
    def test_list_messages_without_queue_url(self, aws_client):
        # makes sure the service is loaded when running the test individually
        aws_client.sqs.list_queues()

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            headers={"Accept": "application/json"},
        )
        assert not response.ok
        assert (
            response.json()["ErrorResponse"]["Error"]["Code"]
            == "AWS.SimpleQueueService.NonExistentQueue"
        ), f"not a json {response.text}"

    @markers.aws.only_localstack
    def test_list_messages_with_invalid_queue_url(self, aws_client):
        # makes sure the service is loaded when running the test individually
        aws_client.sqs.list_queues()

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": "http://localhost:4566/nonsense"},
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 404
        assert response.json()["ErrorResponse"]["Error"]["Code"] == "InvalidAddress"

    @markers.aws.only_localstack
    def test_list_messages_with_non_existent_queue(self, aws_client):
        # makes sure the service is loaded when running the test individually
        aws_client.sqs.list_queues()

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages/us-east-1/000000000000/hopefullydoesnotexist",
            headers={"Accept": "application/json"},
        )
        assert (
            response.json()["ErrorResponse"]["Error"]["Code"]
            == "AWS.SimpleQueueService.NonExistentQueue"
        )

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": "http://localhost:4566/000000000000/hopefullydoesnotexist"},
            headers={"Accept": "application/json"},
        )
        assert (
            response.json()["ErrorResponse"]["Error"]["Code"]
            == "AWS.SimpleQueueService.NonExistentQueue"
        )

    @markers.aws.only_localstack
    def test_list_messages_with_queue_url_in_path(self, sqs_create_queue, aws_client):
        queue_url = sqs_create_queue()

        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-1")
        aws_client.sqs.send_message(QueueUrl=queue_url, MessageBody="message-2")

        account, region, name = parse_queue_url(queue_url)
        # sometimes the region cannot be determined from the queue url, we make no assumptions about this
        # in this test
        region = region or aws_client.sqs.meta.region_name

        response = requests.get(
            f"http://localhost:4566/_aws/sqs/messages/{region}/{account}/{name}",
            headers={"Accept": "application/json"},
        )
        doc = response.json()
        messages = doc["ReceiveMessageResponse"]["ReceiveMessageResult"]["Message"]
        assert len(messages) == 2

        # check that multi-region works correctly
        alt_region = "us-east-2" if region == "us-east-1" else "us-east-1"
        response = requests.get(
            f"http://localhost:4566/_aws/sqs/messages/{alt_region}/{account}/{name}",
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 400
        doc = response.json()
        assert doc["ErrorResponse"]["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue"
