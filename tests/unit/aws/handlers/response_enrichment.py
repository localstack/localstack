import pytest

from localstack.aws.chain import HandlerChain
from localstack.aws.forwarder import create_aws_request_context
from localstack.aws.handlers.response import ResponseMetadataEnricher
from localstack.constants import HEADER_LOCALSTACK_IDENTIFIER
from localstack.http import Response


@pytest.fixture
def response_handler_chain() -> HandlerChain:
    return HandlerChain(response_handlers=[ResponseMetadataEnricher()])


class TestResponseMetadataEnricher:
    def test_adds_header_to_successful_response(self, response_handler_chain):
        context = create_aws_request_context("s3", "ListBuckets")
        response = Response("success", 200)

        response_handler_chain.handle(context, response)

        assert response.headers[HEADER_LOCALSTACK_IDENTIFIER] == "true"

    def test_adds_header_to_error_response(self, response_handler_chain):
        context = create_aws_request_context(
            "opensearch", "DescribeDomain", {"DomainName": "foobar"}
        )
        response = Response(b'{"__type": "ResourceNotFoundException"}', 409)

        response_handler_chain.handle(context, response)

        assert response.headers[HEADER_LOCALSTACK_IDENTIFIER] == "true"
