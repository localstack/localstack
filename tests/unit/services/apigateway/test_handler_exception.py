import pytest
from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.services.apigateway.models import RestApiContainer, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import GatewayExceptionHandler


@pytest.fixture
def exception_handler_chain() -> RestApiGatewayHandlerChain:
    """Returns a dummy chain for testing."""
    return RestApiGatewayHandlerChain(exception_handlers=[GatewayExceptionHandler()])


class TestGatewayResponseHandler:
    @pytest.fixture
    def create_chain_with_response(self, exception_handler_chain):
        """We need to ad a deployment to every chain."""

        def _create_deployment(gateway_responses=None) -> RestApiGatewayHandlerChain:
            chain = exception_handler_chain
            context = RestApiInvocationContext(None)
            context.deployment = RestApiDeployment(RestApiContainer(None), None)

            if gateway_responses:
                context.deployment.localstack_rest_api.gateway_responses = gateway_responses
            chain.context = context

            return chain

        return _create_deployment

    def test_non_gateway_exception(self, create_chain_with_response):
        # create a default Exception that should not be handled by the handler
        handler_chain = create_chain_with_response()
        exception = Exception("Unhandled exception")

        response = Response()
        handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 500
        assert response.json == {"message": "LocalStack Error: Unhandled exception"}

    def test_gateway_exception(self, create_chain_with_response):
        handler_chain = create_chain_with_response()

        # Create an Access Denied exception with no Gateway Response configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 403
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_default_4xx(self, create_chain_with_response):
        # Configure DEFAULT_4XX reaponse
        handler_chain = create_chain_with_response(
            {GatewayResponseType.DEFAULT_4XX: GatewayResponse(statusCode="400")}
        )

        # Create an Access Denied exception with DEFAULT_4xx configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_gateway_response(self, create_chain_with_response):
        # Configure Access Denied response
        handler_chain = create_chain_with_response(
            {GatewayResponseType.ACCESS_DENIED: GatewayResponse(statusCode="400")}
        )

        # Create an Access Denied exception with ACCESS_DENIED configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}
