from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.services.apigateway.models import RestApiContainer, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import GatewayExceptionHandler


class TestGatewayResponseHandler:
    def test_non_gateway_exception(self):
        handler = GatewayExceptionHandler()
        response = Response()

        # create a default Exception that should not be handled by the handler
        exception = Exception()
        handler(None, exception, RestApiInvocationContext(None), response)

        assert response.status_code == 200
        assert response.data == b""

    def test_gateway_exception(self):
        handler = GatewayExceptionHandler()
        response = Response()

        deployment = RestApiDeployment(RestApiContainer(None), None)
        context = RestApiInvocationContext(None)
        context.deployment = deployment

        # Create an Access Denied exception with no Gateway Response configured
        exception = AccessDeniedError("Access Denied")
        handler(None, exception, context, response)

        assert response.status_code == 403
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_default_4xx(self):
        handler = GatewayExceptionHandler()
        response = Response()

        # Configure DEFAULT_4XX
        deployment = RestApiDeployment(RestApiContainer(None), None)
        deployment.localstack_rest_api.gateway_responses = {
            GatewayResponseType.DEFAULT_4XX: GatewayResponse(statusCode="400")
        }
        context = RestApiInvocationContext(None)
        context.deployment = deployment

        # Create an Access Denied exception with DEFAULT_4xx configured
        exception = AccessDeniedError("Access Denied")

        handler(None, exception, context, response)

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_gateway_response(self):
        handler = GatewayExceptionHandler()
        response = Response()

        # Configure Access Denied response
        deployment = RestApiDeployment(RestApiContainer(None), None)
        deployment.localstack_rest_api.gateway_responses = {
            GatewayResponseType.ACCESS_DENIED: GatewayResponse(statusCode="400")
        }
        context = RestApiInvocationContext(None)
        context.deployment = deployment

        # Create an Access Denied exception with ACCESS_DENIED configured
        exception = AccessDeniedError("Access Denied")
        handler(None, exception, context, response)

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}
