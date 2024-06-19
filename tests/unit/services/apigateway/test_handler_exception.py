import pytest
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.services.apigateway.models import RestApiContainer, RestApiDeployment
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
    def add_deployment_to_chain(self):
        def _create_deployment(chain:RestApiGatewayHandlerChain, gateway_responses= None):
            context = RestApiInvocationContext(None)
            context.deployment = RestApiDeployment(RestApiContainer(None), None)
            if gateway_responses:
                context.deployment.localstack_rest_api.gateway_responses = gateway_responses
            chain.context = context

        return _create_deployment

    def test_non_gateway_exception(self, exception_handler_chain):
        # create a default Exception that should not be handled by the handler
        exception = Exception()

        response = Response()
        exception_handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 200
        assert response.data == b""

    def test_gateway_exception(self, exception_handler_chain, add_deployment_to_chain):
        add_deployment_to_chain(exception_handler_chain)

        # Create an Access Denied exception with no Gateway Response configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 403
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_default_4xx(self, exception_handler_chain, add_deployment_to_chain):
        # Configure DEFAULT_4XX
        add_deployment_to_chain(exception_handler_chain, {GatewayResponseType.DEFAULT_4XX: GatewayResponse(statusCode="400")})

        # Create an Access Denied exception with DEFAULT_4xx configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler_chain._call_exception_handlers(exception, response)


        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_gateway_response(self, exception_handler_chain, add_deployment_to_chain):
        # Configure Access Denied response
        add_deployment_to_chain(exception_handler_chain, {
            GatewayResponseType.ACCESS_DENIED: GatewayResponse(statusCode="400")
        })

        # Create an Access Denied exception with ACCESS_DENIED configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler_chain._call_exception_handlers(exception, response)

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}
