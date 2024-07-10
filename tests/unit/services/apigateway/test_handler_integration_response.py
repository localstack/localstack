import pytest

from localstack.aws.api.apigateway import Integration, IntegrationResponse, IntegrationType, Method
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import RestApiInvocationContext
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
def default_context():
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

    context.resource_method = Method(
        methodIntegration=Integration(type=IntegrationType.HTTP), methodResponses={}
    )
    context.context_variables = ContextVariables()
    return context


@pytest.fixture
def create_default_response():
    def _response():
        return Response(
            status=200,
            headers={"content-type": "application/json", "header": ["multi", "header"]},
            response=b'{"foo":"bar"}',
        )

    return _response


@pytest.fixture
def integration_response_handler():
    """Returns a dummy integration response handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext, response: Response):
        return IntegrationResponseHandler()(RestApiGatewayHandlerChain(), context, response)

    return _handler_invoker


class TestHandlerIntegrationResponse:
    def test_proxy_passthrough(
        self, default_context, create_default_response, integration_response_handler
    ):
        og_response = create_default_response()
        response = create_default_response()
        default_context.resource_method["methodIntegration"]["type"] = IntegrationType.AWS_PROXY
        integration_response_handler(default_context, response)
        assert response.response == og_response.response
        assert response.status_code == og_response.status_code
        assert response.headers == og_response.headers

        response = create_default_response()
        default_context.resource_method["methodIntegration"]["type"] = IntegrationType.AWS_PROXY
        integration_response_handler(default_context, response)
        assert response.response == og_response.response
        assert response.status_code == og_response.status_code
        assert response.headers == og_response.headers

    def test_status_code(
        self, default_context, create_default_response, integration_response_handler
    ):
        integration_response = IntegrationResponse(
            statusCode="300",
            selectionPattern="",
            responseParameters=None,
            responseTemplates=None,
        )
        default_context.resource_method["methodIntegration"]["integrationResponses"] = {
            "default": integration_response
        }
        # take the status code from the integration response
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.status_code == 300

        # take the status code from the response override
        response = create_default_response()
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 500)"
        }
        integration_response_handler(default_context, response)
        assert response.status_code == 500

        # invalid values from response override are not taken into account > 599
        response = create_default_response()
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 600)"
        }
        integration_response_handler(default_context, response)
        assert response.status_code == 300

        # invalid values from response override are not taken into account < 100
        response = create_default_response()
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.status = 99)"
        }
        integration_response_handler(default_context, response)
        assert response.status_code == 300

    def test_headers(self, default_context, create_default_response, integration_response_handler):
        integration_response = IntegrationResponse(
            statusCode="200",
            selectionPattern="",
            responseParameters={"method.response.header.header": "'from params'"},
            responseTemplates=None,
        )
        default_context.resource_method["methodIntegration"]["integrationResponses"] = {
            "default": integration_response
        }

        # set constant
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.headers["header"] == "from params"

        # set to body
        response = create_default_response()
        integration_response["responseParameters"] = {
            "method.response.header.header": "integration.response.body"
        }
        integration_response_handler(default_context, response)
        assert response.headers["header"] == '{"foo":"bar"}'

        # override
        response = create_default_response()
        integration_response["responseTemplates"] = {
            "application/json": "#set($context.responseOverride.header.header = 'from override')"
        }
        integration_response_handler(default_context, response)
        assert response.headers["header"] == "from override"

    def test_default_template_selection_behavior(
        self, default_context, create_default_response, integration_response_handler
    ):
        integration_response = IntegrationResponse(
            statusCode="200",
            selectionPattern="",
            responseParameters=None,
            responseTemplates={},
        )
        default_context.resource_method["methodIntegration"]["integrationResponses"] = {
            "default": integration_response
        }
        # if none are set return the original body
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.data == b'{"foo":"bar"}'

        # if no template match, picks the "first"
        integration_response["responseTemplates"]["application/xml"] = "xml"
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.data == b"xml"

        # Match with json
        integration_response["responseTemplates"]["application/json"] = "json"
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.data == b"json"

        # Aws favors json when not math
        response = create_default_response()
        response.headers["content-type"] = "text/html"
        integration_response_handler(default_context, response)
        assert response.data == b"json"

    def test_remapped_headers(
        self, default_context, create_default_response, integration_response_handler
    ):
        integration_response = IntegrationResponse(
            statusCode="200",
            selectionPattern="",
            responseParameters={
                "method.response.header.content-type": "'from params'",
                "method.response.header.connection": "'from params'",
            },
            responseTemplates={"application/json": RESPONSE_OVERRIDES},
        )
        default_context.resource_method["methodIntegration"]["integrationResponses"] = {
            "default": integration_response
        }
        response = create_default_response()
        integration_response_handler(default_context, response)
        assert response.data == b""
        assert response.headers.get("content-type") == "application/json"
        assert response.headers.get("x-amzn-remapped-connection") == "from params"
        assert response.headers.get("x-amzn-remapped-date") == "from override"
        assert response.headers.get("x-amzn-remapped-content-type") == "from override"


RESPONSE_OVERRIDES = """#set($context.responseOverride.header.content-type = 'from override')
#set($context.responseOverride.header.date = 'from override')"""
