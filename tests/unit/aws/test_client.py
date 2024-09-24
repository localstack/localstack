import boto3
import pytest

from localstack.aws.api import RequestContext, ServiceException
from localstack.aws.client import (
    GatewayShortCircuit,
    _ResponseStream,
    botocore_in_memory_endpoint_patch,
    parse_service_exception,
)
from localstack.aws.connect import get_service_endpoint
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
    @pytest.fixture(scope="class", autouse=True)
    def patch_boto_endpoint(self):
        if botocore_in_memory_endpoint_patch.is_applied:
            return

        botocore_in_memory_endpoint_patch.apply()
        yield
        botocore_in_memory_endpoint_patch.undo()

    def test_query_request(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                assert context.operation.name == "DeleteTopic"
                assert context.service.service_name == "sns"
                assert context.service_request == {
                    "TopicArn": "arn:aws:sns:us-east-1:000000000000:test-topic",
                    "Action": "DeleteTopic",
                    "Version": "2010-03-31",
                }
                data = b"""<DeleteTopicResponse xmlns="https://sns.amazonaws.com/doc/2010-03-31/">
                    <ResponseMetadata>
                        <RequestId>f3aa9ac9-3c3d-11df-8235-9dab105e9c32</RequestId>
                    </ResponseMetadata>
                </DeleteTopicResponse>"""
                response.data = data
                response.status_code = 200

        gateway = MockGateway()

        client = boto3.client("sns", endpoint_url=get_service_endpoint())
        GatewayShortCircuit.modify_client(client, gateway)
        delete_topic = client.delete_topic(TopicArn="arn:aws:sns:us-east-1:000000000000:test-topic")
        assert delete_topic["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_query_exception(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                raise ValueError("oh noes")

        gateway = MockGateway()

        client = boto3.client("sns", endpoint_url=get_service_endpoint())
        GatewayShortCircuit.modify_client(client, gateway)

        # FIXME currently, exceptions in the gateway will be handed down to the client and not translated into 500
        #  errors
        with pytest.raises(ValueError):
            client.list_topics()

    def test_query_response(self):
        class MockGateway:
            def handle(self, context: RequestContext, response: Response):
                response.data = b"<ListTopicsResponse><ListTopicsResult><Topics><member><TopicArn>arn:aws:sns:us-east-1:000000000000:test-1d5a154d</TopicArn></member></Topics></ListTopicsResult><ResponseMetadata><RequestId></RequestId></ResponseMetadata></ListTopicsResponse>"
                response.status_code = 202

        gateway = MockGateway()

        client = boto3.client("sns", endpoint_url=get_service_endpoint())
        GatewayShortCircuit.modify_client(client, gateway)

        list_topics = client.list_topics()
        assert list_topics["Topics"] == [
            {"TopicArn": "arn:aws:sns:us-east-1:000000000000:test-1d5a154d"}
        ]
        assert list_topics["ResponseMetadata"]["HTTPStatusCode"] == 202
