import pytest
from werkzeug.datastructures import Headers

from localstack.aws.api.apigateway import Integration, IntegrationResponse, IntegrationType
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    EndpointResponse,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    ApiConfigurationError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import (
    IntegrationResponseHandler,
    InvocationRequestParser,
)
from localstack.services.apigateway.next_gen.execute_api.variables import ContextVariables
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

TEST_API_ID = "test-api"
TEST_API_STAGE = "stage"


class TestSelectionPattern:
    def test_selection_pattern_status_code(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
            ),
            "400": IntegrationResponse(
                statusCode="400",
                selectionPattern="400",
            ),
            "500": IntegrationResponse(
                statusCode="500",
                selectionPattern=r"5\d{2}",
            ),
        }

        def select_int_response(selection_value: str) -> IntegrationResponse:
            return IntegrationResponseHandler.select_integration_response(
                selection_value=selection_value,
                integration_responses=integration_responses,
            )

        int_response = select_int_response("200")
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("400")
        assert int_response["statusCode"] == "400"

        int_response = select_int_response("404")
        # fallback to default
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("500")
        assert int_response["statusCode"] == "500"

        int_response = select_int_response("501")
        assert int_response["statusCode"] == "500"

    def test_selection_pattern_no_default(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
                selectionPattern="200",
            ),
        }

        with pytest.raises(ApiConfigurationError) as e:
            IntegrationResponseHandler.select_integration_response(
                selection_value="404",
                integration_responses=integration_responses,
            )
        assert e.value.message == "Internal server error"

    def test_selection_pattern_string(self):
        integration_responses = {
            "2OO": IntegrationResponse(
                statusCode="200",
            ),
            "400": IntegrationResponse(
                statusCode="400",
                selectionPattern="Malformed.*",
            ),
            "500": IntegrationResponse(
                statusCode="500",
                selectionPattern="Internal.*",
            ),
        }

        def select_int_response(selection_value: str) -> IntegrationResponse:
            return IntegrationResponseHandler.select_integration_response(
                selection_value=selection_value,
                integration_responses=integration_responses,
            )

        # this would basically no error message from AWS lambda
        int_response = select_int_response("")
        assert int_response["statusCode"] == "200"

        int_response = select_int_response("Malformed request")
        assert int_response["statusCode"] == "400"

        int_response = select_int_response("Internal server error")
        assert int_response["statusCode"] == "500"

        int_response = select_int_response("Random error")
        assert int_response["statusCode"] == "200"


@pytest.fixture
def ctx():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    context = RestApiInvocationContext(Request())

    # Frozen deployment populated by the router
    context.deployment = RestApiDeployment(
        account_id=TEST_AWS_ACCOUNT_ID,
        region=TEST_AWS_REGION_NAME,
        rest_api=MergedRestApi(rest_api={}),
    )

    # Context populated by parser handler before creating the invocation request
    context.region = TEST_AWS_REGION_NAME
    context.account_id = TEST_AWS_ACCOUNT_ID
    context.stage = TEST_API_STAGE
    context.api_id = TEST_API_ID

    request = InvocationRequestParser().create_invocation_request(context)
    context.invocation_request = request

    context.integration = Integration(type=IntegrationType.HTTP)
    context.context_variables = ContextVariables()
    context.endpoint_response = EndpointResponse(
        body=b'{"foo":"bar"}',
        status_code=200,
        headers=Headers({"content-type": "application/json", "header": ["multi", "header"]}),
    )
    return context


@pytest.fixture
def integration_response_handler():
    """Returns a dummy integration response handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext):
        return IntegrationResponseHandler()(RestApiGatewayHandlerChain(), context, Response())

    return _handler_invoker


class TestHandlerIntegrationResponse:
    def test_status_code(self, ctx, integration_response_handler):
        integration_response = IntegrationResponse(
            statusCode="300",
            selectionPattern="",
            responseParameters=None,
            responseTemplates=None,
        )
        ctx.integration["integrationResponses"] = {"200": integration_response}
        # take the status code from the integration response
        integration_response_handler(ctx)
        assert ctx.invocation_response["status_code"] == 300

        # take the status code from the response override
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 500)"
        }
        integration_response_handler(ctx)
        assert ctx.invocation_response["status_code"] == 500

        # invalid values from response override are not taken into account > 599
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 600)"
        }
        integration_response_handler(ctx)
        assert ctx.invocation_response["status_code"] == 300

        # invalid values from response override are not taken into account < 100
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 99)"
        }
        integration_response_handler(ctx)
        assert ctx.invocation_response["status_code"] == 300

    def test_headers(self, ctx, integration_response_handler):
        integration_response = IntegrationResponse(
            statusCode="200",
            selectionPattern="",
            responseParameters={"method.response.header.header": "'from params'"},
            responseTemplates=None,
        )
        ctx.integration["integrationResponses"] = {"200": integration_response}

        # set constant
        integration_response_handler(ctx)
        assert ctx.invocation_response["headers"]["header"] == "from params"

        # set to body
        integration_response["responseParameters"] = {
            "method.response.header.header": "integration.response.body"
        }
        integration_response_handler(ctx)
        assert ctx.invocation_response["headers"]["header"] == '{"foo":"bar"}'

        # override
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.header.header = 'from override')"
        }
        integration_response_handler(ctx)
        assert ctx.invocation_response["headers"]["header"] == "from override"

    def test_default_template_selection_behavior(self, ctx, integration_response_handler):
        integration_response = IntegrationResponse(
            statusCode="200",
            selectionPattern="",
            responseParameters=None,
            responseTemplates={},
        )
        ctx.integration["integrationResponses"] = {"200": integration_response}
        # if none are set return the original body
        integration_response_handler(ctx)
        assert ctx.invocation_response["body"] == b'{"foo":"bar"}'

        # if no template match, picks the "first"
        integration_response["responseTemplates"]["application/xml"] = "xml"
        integration_response_handler(ctx)
        assert ctx.invocation_response["body"] == b"xml"

        # Match with json
        integration_response["responseTemplates"]["application/json"] = "json"
        integration_response_handler(ctx)
        assert ctx.invocation_response["body"] == b"json"

        # Aws favors json when not math
        ctx.endpoint_response["headers"]["content-type"] = "text/html"
        integration_response_handler(ctx)
        assert ctx.invocation_response["body"] == b"json"
