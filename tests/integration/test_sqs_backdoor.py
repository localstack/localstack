import pytest
import requests
import xmltodict
from botocore.exceptions import ClientError

from localstack.services.sqs.utils import parse_queue_url
from localstack.utils.aws import aws_stack


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


class TestSqsDeveloperEdpoints:
    @pytest.mark.only_localstack
    def test_list_messages_has_no_side_effects(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-1")
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-2")

        # check that accessing messages for this queue URL does not affect `ApproximateReceiveCount`
        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages", params={"QueueUrl": queue_url}
        )
        attributes = _parse_message_attributes(response.text)
        assert attributes[0]["ApproximateReceiveCount"] == "0"
        assert attributes[1]["ApproximateReceiveCount"] == "0"

        # do a real receive op that has a side effect
        response = sqs_client.receive_message(
            QueueUrl=queue_url, VisibilityTimeout=0, MaxNumberOfMessages=1, AttributeNames=["All"]
        )
        print(response)
        assert response["Messages"][0]["Body"] == "message-1"
        assert response["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "1"

        # check backdoor access again
        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages", params={"QueueUrl": queue_url}
        )
        attributes = _parse_message_attributes(response.text)
        assert attributes[0]["ApproximateReceiveCount"] == "1"
        assert attributes[1]["ApproximateReceiveCount"] == "0"

    @pytest.mark.only_localstack
    def test_list_messages_as_botocore_endpoint_url(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-1")
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-2")

        # use the developer endpoint as boto client URL
        client = aws_stack.connect_to_service(
            "sqs", endpoint_url="http://localhost:4566/_aws/sqs/messages"
        )
        # max messages is ignored
        response = client.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)

        assert len(response["Messages"]) == 2

        assert response["Messages"][0]["Body"] == "message-1"
        assert response["Messages"][1]["Body"] == "message-2"
        assert response["Messages"][0]["Attributes"]["ApproximateReceiveCount"] == "0"
        assert response["Messages"][1]["Attributes"]["ApproximateReceiveCount"] == "0"

    @pytest.mark.only_localstack
    def test_list_messages_with_invalid_action_raises_error(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        client = aws_stack.connect_to_service(
            "sqs", endpoint_url="http://localhost:4566/_aws/sqs/messages"
        )

        with pytest.raises(ClientError) as e:
            client.send_message(QueueUrl=queue_url, MessageBody="foobar")

        assert e.value.response["Error"]["Code"] == "InvalidRequest"
        assert (
            e.value.response["Error"]["Message"]
            == "This endpoint only accepts ReceiveMessage calls"
        )

    @pytest.mark.only_localstack
    def test_list_messages_as_json(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-1")
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-2")

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

    @pytest.mark.only_localstack
    def test_list_messages_without_queue_url(self, sqs_client):
        # makes sure the service is loaded when running the test individually
        sqs_client.list_queues()

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            headers={"Accept": "application/json"},
        )
        assert not response.ok
        assert (
            response.json()["ErrorResponse"]["Error"]["Code"]
            == "AWS.SimpleQueueService.NonExistentQueue"
        ), f"not a json {response.text}"

    @pytest.mark.only_localstack
    def test_list_messages_with_invalid_queue_url(self, sqs_client):
        # makes sure the service is loaded when running the test individually
        sqs_client.list_queues()

        response = requests.get(
            "http://localhost:4566/_aws/sqs/messages",
            params={"QueueUrl": "http://localhost:4566/nonsense"},
            headers={"Accept": "application/json"},
        )
        assert response.status_code == 404
        assert response.json()["ErrorResponse"]["Error"]["Code"] == "InvalidAddress"

    @pytest.mark.only_localstack
    def test_list_messages_with_non_existent_queue(self, sqs_client):
        # makes sure the service is loaded when running the test individually
        sqs_client.list_queues()

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

    @pytest.mark.only_localstack
    def test_list_messages_with_queue_url_in_path(self, sqs_client, sqs_create_queue):
        queue_url = sqs_create_queue()

        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-1")
        sqs_client.send_message(QueueUrl=queue_url, MessageBody="message-2")

        region, account, name = parse_queue_url(queue_url)
        # sometimes the region cannot be determined from the queue url, we make no assumptions about this in this test
        region = region or sqs_client.meta.region_name

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
