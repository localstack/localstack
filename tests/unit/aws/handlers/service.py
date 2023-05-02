import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.service import ServiceExceptionSerializer, ServiceResponseParser
from localstack.aws.protocol.serializer import create_serializer
from localstack.http import Request, Response


@pytest.fixture
def service_response_handler_chain() -> HandlerChain:
    """Returns a dummy chain for testing."""
    return HandlerChain(response_handlers=[ServiceResponseParser()])


class TestServiceResponseHandler:
    def test_use_set_response(self, service_response_handler_chain):
        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_response = {"sure": "why not"}

        service_response_handler_chain.handle(context, Response(status=200))
        assert context.service_response == {"sure": "why not"}

    def test_parse_response(self, service_response_handler_chain):
        context = create_aws_request_context("sqs", "CreateQueue", {"QueueName": "foobar"})
        backend_response = {"QueueUrl": "http://localhost:4566/000000000000/foobar"}
        http_response = create_serializer(context.service).serialize_to_response(
            backend_response, context.operation, context.request.headers, context.request_id
        )

        service_response_handler_chain.handle(context, http_response)
        assert context.service_response == backend_response

    def test_parse_response_with_streaming_response(self, service_response_handler_chain):
        context = create_aws_request_context("s3", "GetObject", {"Bucket": "foo", "Key": "bar.bin"})
        backend_response = {"Body": b"\x00\x01foo", "ContentType": "application/octet-stream"}
        http_response = create_serializer(context.service).serialize_to_response(
            backend_response, context.operation, context.request.headers, context.request_id
        )

        service_response_handler_chain.handle(context, http_response)
        assert context.service_response["ContentLength"] == 5
        assert context.service_response["ContentType"] == "application/octet-stream"
        assert context.service_response["Body"].read() == b"\x00\x01foo"

    def test_common_service_exception(self, service_response_handler_chain):
        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_exception = CommonServiceException(
            "MyCommonException", "oh noes", status_code=409, sender_fault=True
        )

        service_response_handler_chain.handle(context, Response(status=409))
        assert context.service_exception.message == "oh noes"
        assert context.service_exception.code == "MyCommonException"
        assert context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

    def test_service_exception(self, service_response_handler_chain):
        from localstack.aws.api.opensearch import ResourceAlreadyExistsException

        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_exception = ResourceAlreadyExistsException("oh noes")

        response = create_serializer(context.service).serialize_error_to_response(
            context.service_exception, context.operation, context.request.headers
        )

        service_response_handler_chain.handle(context, response)
        assert context.service_exception.message == "oh noes"
        assert context.service_exception.code == "ResourceAlreadyExistsException"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

    def test_service_exception_with_code_from_spec(self, service_response_handler_chain):
        from localstack.aws.api.sqs import QueueDoesNotExist

        context = create_aws_request_context(
            "sqs",
            "SendMessage",
            {"QueueUrl": "http://localhost:4566/000000000000/foobared", "MessageBody": "foo"},
        )
        context.service_exception = QueueDoesNotExist()

        response = create_serializer(context.service).serialize_error_to_response(
            context.service_exception, context.operation, context.request.headers
        )

        service_response_handler_chain.handle(context, response)

        assert context.service_exception.message == ""
        assert context.service_exception.code == "AWS.SimpleQueueService.NonExistentQueue"
        assert context.service_exception.sender_fault
        assert context.service_exception.status_code == 400

    def test_sets_exception_from_error_response(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", {"DomainName": "foobar"}
        )
        response = Response(
            b'{"__type": "ResourceNotFoundException", "message": "Domain not found: foobar"}',
            409,
        )
        service_response_handler_chain.handle(context, response)

        assert context.service_exception.message == "Domain not found: foobar"
        assert context.service_exception.code == "ResourceNotFoundException"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 409

        assert context.service_response is None

    def test_nothing_set_does_nothing(self, service_response_handler_chain):
        context = RequestContext()
        context.request = Request("GET", "/_localstack/health")

        service_response_handler_chain.handle(context, Response("ok", 200))

        assert context.service_exception is None
        assert context.service_response is None

    def test_invalid_exception_does_nothing(self, service_response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", {"DomainName": "foobar"}
        )
        context.service_exception = ValueError()
        service_response_handler_chain.handle(context, Response(status=500))

        assert context.service_response is None
        assert isinstance(context.service_exception, ValueError)

    @pytest.mark.parametrize(
        "message, output", [("", "not yet implemented or pro feature"), ("Ups!", "Ups!")]
    )
    def test_not_implemented_error(self, service_response_handler_chain, message, output):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", {"DomainName": "foobar"}
        )
        not_implemented_exception = NotImplementedError(message)

        ServiceExceptionSerializer().create_exception_response(not_implemented_exception, context)

        assert output in context.service_exception.message
        assert context.service_exception.code == "InternalFailure"
        assert not context.service_exception.sender_fault
        assert context.service_exception.status_code == 501
