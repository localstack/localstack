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

BINARY_DATA_1 = b"\x1f\x8b\x08\x00\x14l\xeec\x02\xffK\xce\xcf-(J-.NMQHI,I\xd4Q(\xce\xc8/\xcdIQHJU\xc8\xcc+K\xcc\xc9LQ\x08\rq\xd3\xb5P(.)\xca\xccK\x07\x00\xb89\x10W/\x00\x00\x00"
BINARY_DATA_2 = b"\x1f\x8b\x08\x00\x14l\xeec\x02\xffK\xce\xcf-(J-.NMQHI,IT0\xd2Q(\xce\xc8/\xcdIQHJU\xc8\xcc+K\xcc\xc9LQ\x08\rq\xd3\xb5P(.)\xca\xccKWH*-QH\xc9LKK-J\xcd+\x01\x00\x99!\xedI?\x00\x00\x00"
BINARY_DATA_1_SAFE = b"\x1f\xef\xbf\xbd\x08\x00\x14l\xef\xbf\xbdc\x02\xef\xbf\xbdK\xef\xbf\xbd\xef\xbf\xbd-(J-.NMQHI,I\xef\xbf\xbdQ(\xef\xbf\xbd\xef\xbf\xbd/\xef\xbf\xbdIQHJU\xef\xbf\xbd\xef\xbf\xbd+K\xef\xbf\xbd\xef\xbf\xbdLQ\x08\rq\xd3\xb5P(.)\xef\xbf\xbd\xef\xbf\xbdK\x07\x00\xef\xbf\xbd9\x10W/\x00\x00\x00"


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


class TestIntegrationResponseBinaryHandling:
    """
    https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-payload-encodings-workflow.html
    When AWS differentiates between "text" and "binary" types, it means if the MIME type of the Content-Type or Accept
    header matches one of the binaryMediaTypes configured
    """

    @pytest.mark.parametrize(
        "response_content_type,client_accept,binary_medias,content_handling, expected",
        [
            (None, None, None, None, "utf8"),
            (None, None, None, "CONVERT_TO_BINARY", "b64-decoded"),
            (None, None, None, "CONVERT_TO_TEXT", "utf8"),
            ("text/plain", "text/plain", ["image/png"], None, "utf8"),
            ("text/plain", "text/plain", ["image/png"], "CONVERT_TO_BINARY", "b64-decoded"),
            ("text/plain", "text/plain", ["image/png"], "CONVERT_TO_TEXT", "utf8"),
            ("text/plain", "image/png", ["image/png"], None, "b64-decoded"),
            ("text/plain", "image/png", ["image/png"], "CONVERT_TO_BINARY", "b64-decoded"),
            ("text/plain", "image/png", ["image/png"], "CONVERT_TO_TEXT", "utf8"),
            ("image/png", "text/plain", ["image/png"], None, "b64-encoded"),
            ("image/png", "text/plain", ["image/png"], "CONVERT_TO_BINARY", None),
            ("image/png", "text/plain", ["image/png"], "CONVERT_TO_TEXT", "b64-encoded"),
            ("image/png", "image/png", ["image/png"], None, None),
            ("image/png", "image/png", ["image/png"], "CONVERT_TO_BINARY", None),
            ("image/png", "image/png", ["image/png"], "CONVERT_TO_TEXT", "b64-encoded"),
        ],
    )
    @pytest.mark.parametrize(
        "input_data,possible_values",
        [
            (
                BINARY_DATA_1,
                {
                    "b64-encoded": b"H4sIABRs7mMC/0vOzy0oSi0uTk1RSEksSdRRKM7IL81JUUhKVcjMK0vMyUxRCA1x07VQKC4pysxLBwC4ORBXLwAAAA==",
                    "b64-decoded": None,
                    "utf8": BINARY_DATA_1_SAFE.decode(),
                },
            ),
            (
                b"H4sIABRs7mMC/0vOzy0oSi0uTk1RSEksSVQw0lEozsgvzUlRSEpVyMwrS8zJTFEIDXHTtVAoLinKzEtXSCotUUjJTEtLLUrNKwEAmSHtST8AAAA=",
                {
                    "b64-encoded": b"SDRzSUFCUnM3bU1DLzB2T3p5MG9TaTB1VGsxUlNFa3NTVlF3MGxFb3pzZ3Z6VWxSU0VwVnlNd3JTOHpKVEZFSURYSFR0VkFvTGluS3pFdFhTQ290VVVqSlRFdExMVXJOS3dFQW1TSHRTVDhBQUFBPQ==",
                    "b64-decoded": BINARY_DATA_2,
                    "utf8": "H4sIABRs7mMC/0vOzy0oSi0uTk1RSEksSVQw0lEozsgvzUlRSEpVyMwrS8zJTFEIDXHTtVAoLinKzEtXSCotUUjJTEtLLUrNKwEAmSHtST8AAAA=",
                },
            ),
            (
                b"my text string",
                {
                    "b64-encoded": b"bXkgdGV4dCBzdHJpbmc=",
                    "b64-decoded": b"\x9b+^\xc6\xdb-\xae)\xe0",
                    "utf8": "my text string",
                },
            ),
        ],
        ids=["binary", "b64-encoded", "text"],
    )
    def test_convert_binary(
        self,
        response_content_type,
        client_accept,
        binary_medias,
        content_handling,
        expected,
        input_data,
        possible_values,
        ctx,
    ):
        ctx.endpoint_response["headers"]["Content-Type"] = response_content_type
        ctx.invocation_request["headers"]["Accept"] = client_accept
        ctx.deployment.rest_api.rest_api["binaryMediaTypes"] = binary_medias
        convert = IntegrationResponseHandler.convert_body

        outcome = possible_values.get(expected, input_data)
        if outcome is None:
            with pytest.raises(Exception):
                convert(body=input_data, context=ctx, content_handling=content_handling)
        else:
            converted_body = convert(
                body=input_data, context=ctx, content_handling=content_handling
            )
            assert converted_body == outcome
