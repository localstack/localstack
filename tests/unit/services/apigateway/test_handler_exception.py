import pytest
from rolo import Response

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import GatewayExceptionHandler
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME


class TestGatewayResponseHandler:
    @pytest.fixture
    def get_context(self):
        def _create_context_with_deployment(gateway_responses=None) -> RestApiInvocationContext:
            context = RestApiInvocationContext(None)
            context.deployment = RestApiDeployment(
                account_id=TEST_AWS_ACCOUNT_ID,
                region=TEST_AWS_REGION_NAME,
                rest_api=MergedRestApi(None),
            )
            if gateway_responses:
                context.deployment.rest_api.gateway_responses = gateway_responses
            return context

        return _create_context_with_deployment

    def test_non_gateway_exception(self, get_context):
        exception_handler = GatewayExceptionHandler()

        # create a default Exception that should not be handled by the handler
        exception = Exception("Unhandled exception")

        response = Response()
        exception_handler(chain=None, exception=exception, context=get_context(), response=response)

        assert response.status_code == 500
        assert response.data == b"Error in apigateway invocation: Unhandled exception"

    def test_gateway_exception(self, get_context):
        exception_handler = GatewayExceptionHandler()

        # Create an Access Denied exception with no Gateway Response configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler(chain=None, exception=exception, context=get_context(), response=response)

        assert response.status_code == 403
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_default_4xx(self, get_context):
        exception_handler = GatewayExceptionHandler()

        # Configure DEFAULT_4XX response
        gateway_responses = {GatewayResponseType.DEFAULT_4XX: GatewayResponse(statusCode="400")}

        # Create an Access Denied exception with DEFAULT_4xx configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler(
            chain=None,
            exception=exception,
            context=get_context(gateway_responses),
            response=response,
        )

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}

    def test_gateway_exception_with_gateway_response(self, get_context):
        exception_handler = GatewayExceptionHandler()

        # Configure Access Denied response
        gateway_responses = {GatewayResponseType.ACCESS_DENIED: GatewayResponse(statusCode="400")}

        # Create an Access Denied exception with ACCESS_DENIED configured
        exception = AccessDeniedError("Access Denied")
        response = Response()
        exception_handler(
            chain=None,
            exception=exception,
            context=get_context(gateway_responses),
            response=response,
        )

        assert response.status_code == 400
        assert response.json == {"message": "Access Denied"}
