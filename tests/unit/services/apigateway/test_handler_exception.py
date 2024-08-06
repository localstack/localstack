import pytest

from localstack.aws.api.apigateway import GatewayResponse, GatewayResponseType
from localstack.http import Request
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    AccessDeniedError,
    BaseGatewayException,
    UnauthorizedError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import GatewayExceptionHandler
from localstack.services.apigateway.next_gen.execute_api.router import ApiGatewayEndpoint
from localstack.services.apigateway.next_gen.execute_api.variables import ContextVariables
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME


class TestGatewayResponse:
    def test_base_response(self):
        with pytest.raises(BaseGatewayException) as e:
            raise BaseGatewayException()
        assert e.value.message == "Unimplemented Response"

    def test_subclassed_response(self):
        with pytest.raises(BaseGatewayException) as e:
            raise AccessDeniedError("Access Denied")
        assert e.value.message == "Access Denied"
        assert e.value.type == GatewayResponseType.ACCESS_DENIED


@pytest.fixture
def apigw_response():
    return ApiGatewayEndpoint.create_response(Request())


class TestGatewayResponseHandler:
    @pytest.fixture
    def get_context(self):
        def _create_context_with_deployment(gateway_responses=None) -> RestApiInvocationContext:
            context = RestApiInvocationContext(Request())
            context.deployment = RestApiDeployment(
                account_id=TEST_AWS_ACCOUNT_ID,
                region=TEST_AWS_REGION_NAME,
                rest_api=MergedRestApi(None),
            )
            context.context_variables = ContextVariables(requestId="REQUEST_ID")
            if gateway_responses:
                context.deployment.rest_api.gateway_responses = gateway_responses
            return context

        return _create_context_with_deployment

    def test_non_gateway_exception(self, get_context, apigw_response):
        exception_handler = GatewayExceptionHandler()

        # create a default Exception that should not be handled by the handler
        exception = Exception("Unhandled exception")

        exception_handler(
            chain=RestApiGatewayHandlerChain(),
            exception=exception,
            context=get_context(),
            response=apigw_response,
        )

        assert apigw_response.status_code == 500
        assert apigw_response.data == b"Error in apigateway invocation: Unhandled exception"

    def test_gateway_exception(self, get_context, apigw_response):
        exception_handler = GatewayExceptionHandler()

        # Create an UnauthorizedError exception with no Gateway Response configured
        exception = UnauthorizedError("Unauthorized")
        exception_handler(
            chain=RestApiGatewayHandlerChain(),
            exception=exception,
            context=get_context(),
            response=apigw_response,
        )

        assert apigw_response.status_code == 401
        assert apigw_response.json == {"message": "Unauthorized"}
        assert apigw_response.headers.get("x-amzn-errortype") == "UnauthorizedException"

    def test_gateway_exception_with_default_4xx(self, get_context, apigw_response):
        exception_handler = GatewayExceptionHandler()

        # Configure DEFAULT_4XX response
        gateway_responses = {GatewayResponseType.DEFAULT_4XX: GatewayResponse(statusCode="400")}

        # Create an UnauthorizedError exception with DEFAULT_4xx configured
        exception = UnauthorizedError("Unauthorized")
        exception_handler(
            chain=RestApiGatewayHandlerChain(),
            exception=exception,
            context=get_context(gateway_responses),
            response=apigw_response,
        )

        assert apigw_response.status_code == 400
        assert apigw_response.json == {"message": "Unauthorized"}
        assert apigw_response.headers.get("x-amzn-errortype") == "UnauthorizedException"

    def test_gateway_exception_with_gateway_response(self, get_context, apigw_response):
        exception_handler = GatewayExceptionHandler()

        # Configure Access Denied response
        gateway_responses = {GatewayResponseType.UNAUTHORIZED: GatewayResponse(statusCode="405")}

        # Create an UnauthorizedError exception with UNAUTHORIZED configured
        exception = UnauthorizedError("Unauthorized")
        exception_handler(
            chain=RestApiGatewayHandlerChain(),
            exception=exception,
            context=get_context(gateway_responses),
            response=apigw_response,
        )

        assert apigw_response.status_code == 405
        assert apigw_response.json == {"message": "Unauthorized"}
        assert apigw_response.headers.get("x-amzn-errortype") == "UnauthorizedException"

    def test_gateway_exception_access_denied(self, get_context, apigw_response):
        # special case where the `Message` field is capitalized
        exception_handler = GatewayExceptionHandler()

        # Create an AccessDeniedError exception with no Gateway Response configured
        exception = AccessDeniedError("Access Denied")
        exception_handler(
            chain=RestApiGatewayHandlerChain(),
            exception=exception,
            context=get_context(),
            response=apigw_response,
        )

        assert apigw_response.status_code == 403
        assert apigw_response.json == {"Message": "Access Denied"}
        assert apigw_response.headers.get("x-amzn-errortype") == "AccessDeniedException"
