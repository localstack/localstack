import pytest

from localstack.aws.api import CommonServiceException, RequestContext
from localstack.aws.chain import HandlerChain
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.service import ServiceResponseParser
from localstack.aws.protocol.serializer import create_serializer
from localstack.http import Request, Response


@pytest.fixture
def chain() -> HandlerChain:
    """Returns a dummy chain for testing."""
    return HandlerChain()


@pytest.fixture
def handler() -> ServiceResponseParser:
    return ServiceResponseParser()


class TestServiceResponseHandler:
    def test_use_set_response(self, chain, handler):
        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_response = {"sure": "why not"}

        handler(chain, context, Response(status=200))
        assert context.service_response == {"sure": "why not"}

    def test_parse_response(self, chain, handler):
        context = create_aws_request_context("sqs", "CreateQueue", {"QueueName": "foobar"})
        backend_response = {"QueueUrl": "http://localhost:4566/000000000000/foobar"}
        http_response = create_serializer(context.service).serialize_to_response(
            backend_response, context.operation
        )

        handler(chain, context, http_response)
        assert context.service_response == backend_response

    def test_common_service_exception(self, chain, handler):
        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_exception = CommonServiceException(
            "InvalidTypeException", "oh noes", status_code=409, sender_fault=True
        )

        handler(chain, context, Response(status=409))
        assert context.service_response == {
            "Error": {"Code": "InvalidTypeException", "Message": "oh noes"}
        }

    def test_service_exception(self, chain, handler):
        from localstack.aws.api.opensearch import ResourceAlreadyExistsException

        context = create_aws_request_context("opensearch", "CreateDomain", {"DomainName": "foobar"})
        context.service_exception = ResourceAlreadyExistsException("oh noes")

        response = create_serializer(context.service).serialize_error_to_response(
            context.service_exception, context.operation
        )

        handler(chain, context, response)
        assert context.service_response == {
            "Error": {"Code": "ResourceAlreadyExistsException", "Message": "oh noes"}
        }

    def test_nothing_set_does_nothing(self, chain, handler):
        context = RequestContext()
        context.request = Request("GET", "/health")

        handler(chain, context, Response("ok", 200))

        assert context.service_exception is None
        assert context.service_response is None
