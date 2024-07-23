import pytest
from werkzeug.datastructures.headers import Headers

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Request
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    InvocationResponse,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import MethodResponseHandler
from localstack.services.apigateway.next_gen.execute_api.router import ApiGatewayEndpoint


@pytest.fixture
def ctx():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    context = RestApiInvocationContext(Request())
    context.integration = Integration(type=IntegrationType.HTTP)
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


@pytest.fixture
def apigw_response():
    return ApiGatewayEndpoint.create_response(Request())


class TestHandlerMethodResponse:
    def test_empty(self, method_response_handler, ctx, apigw_response):
        method_response_handler(ctx, apigw_response)
        assert apigw_response.data == b""
        assert apigw_response.status_code == 200
        assert apigw_response.headers["Content-Type"] == "application/json"

    def test_json_body(self, method_response_handler, ctx, apigw_response):
        ctx.invocation_response["body"] = b"{}"
        method_response_handler(ctx, apigw_response)
        assert apigw_response.data == b"{}"
        assert apigw_response.status_code == 200
        assert apigw_response.headers["Content-Type"] == "application/json"

    def test_remap_headers(self, method_response_handler, ctx, apigw_response):
        ctx.invocation_response["headers"] = Headers(
            {"Connection": "from-common", "Authorization": "from-non-proxy"}
        )
        method_response_handler(ctx, apigw_response)
        assert apigw_response.headers["x-amzn-Remapped-Authorization"] == "from-non-proxy"
        assert apigw_response.headers["x-amzn-Remapped-Connection"] == "from-common"
        assert apigw_response.headers["Connection"] == "keep-alive"
        assert not apigw_response.headers.get("Authorization")

    def test_drop_headers(self, method_response_handler, ctx, apigw_response):
        ctx.integration["type"] = IntegrationType.HTTP_PROXY
        ctx.invocation_response["headers"] = Headers(
            {"Transfer-Encoding": "from-common", "Via": "from-http-proxy"}
        )
        method_response_handler(ctx, apigw_response)
        assert not apigw_response.headers.get("Transfer-Encoding")
        assert not apigw_response.headers.get("Via")
