import pytest
from werkzeug.datastructures.headers import Headers

from localstack.aws.api.apigateway import Integration, IntegrationType, Method
from localstack.http import Request, Response
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    InvocationResponse,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import MethodResponseHandler
from localstack.services.apigateway.next_gen.execute_api.variables import ContextVariables

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
    context.api_id = TEST_API_ID
    context.resource_method = Method(methodIntegration=Integration(type=IntegrationType.HTTP))
    context.invocation_response = InvocationResponse(
        body=b"",
        status_code=200,
        headers=Headers(),
    )

    return context


@pytest.fixture
def method_response_handler():
    """Returns a dummy integration response handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext, response):
        return MethodResponseHandler()(RestApiGatewayHandlerChain(), context, response)

    return _handler_invoker


class TestHandlerMethodResponse:
    def test_empty(self, method_response_handler, ctx):
        response = Response()
        method_response_handler(ctx, response)
        assert response.data == b""
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"
        assert response.headers["x-amzn-RequestId"] == "request-id"
        assert response.headers.get("X-Amzn-Trace-Id")
        assert response.headers.get("x-amz-apigw-id")

    def test_json_body(self, method_response_handler, ctx):
        response = Response()
        ctx.invocation_response["body"] = b"{}"
        method_response_handler(ctx, response)
        assert response.data == b"{}"
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/json"

    def test_remap_headers(self, method_response_handler, ctx):
        response = Response()
        ctx.invocation_response["headers"] = Headers(
            {"Connection": "from-common", "Authorization": "from-non-proxy"}
        )
        method_response_handler(ctx, response)
        assert response.headers["x-amzn-Remapped-Authorization"] == "from-non-proxy"
        assert response.headers["x-amzn-Remapped-Connection"] == "from-common"
        assert not response.headers.get("Authorization")
        assert not response.headers.get("Connection")

    def test_drop_headers(self, method_response_handler, ctx):
        response = Response()
        ctx.resource_method["methodIntegration"]["type"] = IntegrationType.HTTP_PROXY
        ctx.invocation_response["headers"] = Headers(
            {"Transfer-Encoding": "from-common", "Via": "from-http-proxy"}
        )
        method_response_handler(ctx, response)
        assert not response.headers.get("Transfer-Encoding")
        assert not response.headers.get("Via")
