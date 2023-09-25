import boto3
import pytest

from localstack.aws.api import RequestContext, ServiceException
from localstack.aws.client import GatewayShortCircuit, _ResponseStream, parse_service_exception
from localstack.http import Response


def test_parse_service_exception():
    response = Response(status=400)
    parsed_response = {
        "Error": {
            "Code": "InvalidSubnetID.NotFound",
            "Message": "The subnet ID 'vpc-test' does not exist",
        }
    }
    exception = parse_service_exception(response, parsed_response)
    assert exception
    assert isinstance(exception, ServiceException)
    assert exception.code == "InvalidSubnetID.NotFound"
    assert exception.message == "The subnet ID 'vpc-test' does not exist"
    assert exception.status_code == 400
    assert not exception.sender_fault
    # Ensure that the parsed exception does not have the "Error" field from the botocore response dict
    assert not hasattr(exception, "Error")
    assert not hasattr(exception, "error")


class TestResponseStream:
    def test_read(self):
        response = Response(b"foobar")

        with _ResponseStream(response) as stream:
            assert stream.read(3) == b"foo"
            assert stream.read(3) == b"bar"

    def test_read_with_generator_response(self):
        def _gen():
            yield b"foo"
            yield b"bar"

        response = Response(_gen())

        with _ResponseStream(response) as stream:
            assert stream.read(2) == b"fo"
            # currently the response stream will not buffer across the next line
            assert stream.read(4) == b"o"
            assert stream.read(4) == b"bar"

    def test_as_iterator(self):
        def _gen():
            yield b"foo"
            yield b"bar"

        response = Response(_gen())

        with _ResponseStream(response) as stream:
            assert next(stream) == b"foo"
            assert next(stream) == b"bar"
            with pytest.raises(StopIteration):
                next(stream)


class TestGatewayShortCircuit:
    def test_query_request(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                assert context.operation.name == "DeleteQueue"
                assert context.service.service_name == "sqs"
                assert context.service_request == {
                    "QueueUrl": "http://example.com/queue",
                    "Action": "DeleteQueue",
                    "Version": "2012-11-05",
                }

                response.data = b"<DeleteQueueResponse><ResponseMetadata><RequestId></RequestId></ResponseMetadata></DeleteQueueResponse>"
                response.status_code = 200

        gateway = MockGateway()

        client = boto3.client("sqs")
        GatewayShortCircuit.modify_client(client, gateway)

        response = client.delete_queue(QueueUrl="http://example.com/queue")
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_query_exception(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                raise ValueError("oh noes")

        gateway = MockGateway()

        client = boto3.client("sqs")
        GatewayShortCircuit.modify_client(client, gateway)

        # FIXME currently, exceptions in the gateway will be handed down to the client and not translated into 500
        #  errors
        with pytest.raises(ValueError):
            client.list_queues()

    def test_query_response(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                response.data = b"<ListQueuesResponse><ListQueuesResult><QueueUrl>http://example.com/queue</QueueUrl></ListQueuesResult><ResponseMetadata><RequestId></RequestId></ResponseMetadata></ListQueuesResponse>"
                response.status_code = 202

        gateway = MockGateway()

        client = boto3.client("sqs")
        GatewayShortCircuit.modify_client(client, gateway)

        response = client.list_queues()
        assert response["QueueUrls"] == ["http://example.com/queue"]
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 202
