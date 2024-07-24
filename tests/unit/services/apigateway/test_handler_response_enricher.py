import pytest

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Request
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import (
    InvocationResponseEnricher,
)
from localstack.services.apigateway.next_gen.execute_api.router import ApiGatewayEndpoint
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
    GatewayResponseContextVarsError,
)

TEST_API_ID = "test-api"
TEST_REQUEST_ID = "request-id"


@pytest.fixture
def ctx():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    context = RestApiInvocationContext(Request())
    context.context_variables = ContextVariables(requestId=TEST_REQUEST_ID)
    context.integration = Integration(type=IntegrationType.HTTP)

    return context


@pytest.fixture
def response_enricher_handler():
    """Returns a dummy integration response handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext, response):
        return InvocationResponseEnricher()(RestApiGatewayHandlerChain(), context, response)

    return _handler_invoker


@pytest.fixture
def apigw_response():
    return ApiGatewayEndpoint.create_response(Request())


class TestResponseEnricherHandler:
    def test_empty_response(self, ctx, response_enricher_handler, apigw_response):
        response_enricher_handler(ctx, apigw_response)
        assert apigw_response.headers.get("Content-Type") == "application/json"
        assert apigw_response.headers.get("Connection") == "keep-alive"
        assert apigw_response.headers.get("x-amzn-RequestId") == TEST_REQUEST_ID
        assert apigw_response.headers.get("x-amz-apigw-id") is not None
        assert apigw_response.headers.get("X-Amzn-Trace-Id") is not None

    def test_http_proxy_no_trace_id(self, ctx, response_enricher_handler, apigw_response):
        ctx.integration["type"] = IntegrationType.HTTP_PROXY
        response_enricher_handler(ctx, apigw_response)
        assert apigw_response.headers.get("Content-Type") == "application/json"
        assert apigw_response.headers.get("Connection") == "keep-alive"
        assert apigw_response.headers.get("x-amzn-RequestId") == TEST_REQUEST_ID
        assert apigw_response.headers.get("x-amz-apigw-id") is not None
        assert apigw_response.headers.get("X-Amzn-Trace-Id") is None

    def test_error_no_trace_id(self, ctx, response_enricher_handler, apigw_response):
        ctx.context_variables["error"] = GatewayResponseContextVarsError(message="error")
        response_enricher_handler(ctx, apigw_response)
        assert apigw_response.headers.get("Content-Type") == "application/json"
        assert apigw_response.headers.get("Connection") == "keep-alive"
        assert apigw_response.headers.get("x-amzn-RequestId") == TEST_REQUEST_ID
        assert apigw_response.headers.get("x-amz-apigw-id") is not None
        assert apigw_response.headers.get("X-Amzn-Trace-Id") is None

    def test_error_at_routing(self, ctx, response_enricher_handler, apigw_response):
        # in the case where we fail early, in routing for example, we do not have the integration in the context yet
        ctx.integration = None
        response_enricher_handler(ctx, apigw_response)
        assert apigw_response.headers.get("Content-Type") == "application/json"
        assert apigw_response.headers.get("Connection") == "keep-alive"
        assert apigw_response.headers.get("x-amzn-RequestId") == TEST_REQUEST_ID
        assert apigw_response.headers.get("x-amz-apigw-id") is not None
        assert apigw_response.headers.get("X-Amzn-Trace-Id") is None
