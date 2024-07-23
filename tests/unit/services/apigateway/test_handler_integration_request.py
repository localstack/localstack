from http import HTTPMethod

import pytest

from localstack.aws.api.apigateway import Integration, IntegrationType
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    UnsupportedMediaTypeError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import (
    IntegrationRequestHandler,
    InvocationRequestParser,
)
from localstack.services.apigateway.next_gen.execute_api.handlers.integration_request import (
    PassthroughBehavior,
)
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
)
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

TEST_API_ID = "test-api"
TEST_API_STAGE = "stage"


@pytest.fixture
def default_context():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    context = RestApiInvocationContext(
        Request(
            method=HTTPMethod.POST,
            headers={"header": ["header1", "header2"]},
            path=f"{TEST_API_STAGE}/resource/path",
            query_string="qs=qs1&qs=qs2",
        )
    )

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

    # add path_parameters from the router parser
    request["path_parameters"] = {"proxy": "path"}

    context.integration = Integration(
        type=IntegrationType.HTTP,
        requestParameters=None,
        uri="https://example.com",
        httpMethod="POST",
    )
    context.context_variables = ContextVariables(
        resourceId="resource-id",
        apiId=TEST_API_ID,
        httpMethod="POST",
        path=f"{TEST_API_STAGE}/resource/{{proxy}}",
        resourcePath="/resource/{proxy}",
        stage=TEST_API_STAGE,
    )

    return context


@pytest.fixture
def integration_request_handler():
    """Returns a dummy integration request handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext):
        return IntegrationRequestHandler()(RestApiGatewayHandlerChain(), context, Response())

    return _handler_invoker


class TestHandlerIntegrationRequest:
    def test_noop(self, integration_request_handler, default_context):
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b""
        assert default_context.integration_request["headers"]["Accept"] == "application/json"
        assert default_context.integration_request["http_method"] == "POST"
        assert default_context.integration_request["query_string_parameters"] == {}
        assert default_context.integration_request["uri"] == "https://example.com"

    def test_passthrough_never(self, integration_request_handler, default_context):
        default_context.integration["passthroughBehavior"] = PassthroughBehavior.NEVER

        # With no template, it is expected to raise
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(default_context)
        assert e.match("Unsupported Media Type")

        # With a non-matching template it should raise
        default_context.integration["requestTemplates"] = {"application/xml": "#Empty"}
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(default_context)
        assert e.match("Unsupported Media Type")

        # With a matching template it should use it
        default_context.integration["requestTemplates"] = {"application/json": '{"foo":"bar"}'}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b'{"foo":"bar"}'

    def test_passthrough_when_no_match(self, integration_request_handler, default_context):
        default_context.integration["passthroughBehavior"] = PassthroughBehavior.WHEN_NO_MATCH
        # When no template are created it should passthrough
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b""

        # when a non matching template is found it should passthrough
        default_context.integration["requestTemplates"] = {"application/xml": '{"foo":"bar"}'}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b""

        # when a matching template is found, it should use it
        default_context.integration["requestTemplates"] = {"application/json": '{"foo":"bar"}'}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b'{"foo":"bar"}'

    def test_passthrough_when_no_templates(self, integration_request_handler, default_context):
        default_context.integration["passthroughBehavior"] = PassthroughBehavior.WHEN_NO_TEMPLATES
        # If a non matching template is found, it should raise
        default_context.integration["requestTemplates"] = {"application/xml": ""}
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(default_context)
        assert e.match("Unsupported Media Type")

        # If a matching template is found, it should use it
        default_context.integration["requestTemplates"] = {"application/json": '{"foo":"bar"}'}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b'{"foo":"bar"}'

        # If no template were created, it should passthrough
        default_context.integration["requestTemplates"] = {}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b""

    def test_default_template(self, integration_request_handler, default_context):
        # if no matching template, use the default
        default_context.integration["requestTemplates"] = {"$default": '{"foo":"bar"}'}
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b'{"foo":"bar"}'

        # If there is a matching template, use it instead
        default_context.integration["requestTemplates"] = {
            "$default": '{"foo":"bar"}',
            "application/json": "Matching Template",
        }
        integration_request_handler(default_context)
        assert default_context.integration_request["body"] == b"Matching Template"

    def test_request_parameters(self, integration_request_handler, default_context):
        default_context.integration["requestParameters"] = {
            "integration.request.path.path": "method.request.path.proxy",
            "integration.request.querystring.qs": "method.request.querystring.qs",
            "integration.request.header.header": "method.request.header.header",
        }
        default_context.integration["uri"] = "https://example.com/{path}"
        integration_request_handler(default_context)
        # TODO this test will fail when we implement uri mapping
        assert default_context.integration_request["uri"] == "https://example.com/path"
        assert default_context.integration_request["query_string_parameters"] == {"qs": "qs2"}
        headers = default_context.integration_request["headers"]
        assert headers.get("Accept") == "application/json"
        assert headers.get("header") == "header2"

    def test_request_override(self, integration_request_handler, default_context):
        default_context.integration["requestParameters"] = {
            "integration.request.path.path": "method.request.path.path",
            "integration.request.querystring.qs": "method.request.multivaluequerystring.qs",
            "integration.request.header.header": "method.request.header.header",
        }
        default_context.integration["uri"] = "https://example.com/{path}"
        default_context.integration["requestTemplates"] = {"application/json": REQUEST_OVERRIDE}
        integration_request_handler(default_context)
        assert default_context.integration_request["uri"] == "https://example.com/pathOverride"
        assert default_context.integration_request["query_string_parameters"] == {
            "qs": "queryOverride"
        }
        headers = default_context.integration_request["headers"]
        assert headers.get("Accept") == "application/json"
        assert headers.get("header") == "headerOverride"
        assert headers.getlist("multivalue") == ["1header", "2header"]

    def test_request_override_casing(self, integration_request_handler, default_context):
        default_context.integration["requestParameters"] = {
            "integration.request.header.myHeader": "method.request.header.header",
        }
        default_context.integration["requestTemplates"] = {
            "application/json": '#set($context.requestOverride.header.myheader = "headerOverride")'
        }
        integration_request_handler(default_context)
        # TODO: for now, it's up to the integration to properly merge headers (`requests` does it automatically)
        headers = default_context.integration_request["headers"]
        assert headers.get("Accept") == "application/json"
        assert headers.getlist("myHeader") == ["header2", "headerOverride"]
        assert headers.getlist("myheader") == ["header2", "headerOverride"]

    def test_multivalue_mapping(self, integration_request_handler, default_context):
        default_context.integration["requestParameters"] = {
            "integration.request.header.multi": "method.request.multivalueheader.header",
            "integration.request.querystring.multi": "method.request.multivaluequerystring.qs",
        }
        integration_request_handler(default_context)
        assert default_context.integration_request["headers"]["multi"] == "header1,header2"
        assert default_context.integration_request["query_string_parameters"]["multi"] == [
            "qs1",
            "qs2",
        ]

    def test_integration_uri_path_params_undefined(
        self, integration_request_handler, default_context
    ):
        default_context.integration["requestParameters"] = {
            "integration.request.path.path": "method.request.path.wrongvalue",
        }
        default_context.integration["uri"] = "https://example.com/{path}"
        integration_request_handler(default_context)
        assert default_context.integration_request["uri"] == "https://example.com/{path}"

    def test_integration_uri_stage_variables(self, integration_request_handler, default_context):
        default_context.stage_variables = {
            "stageVar": "stageValue",
        }
        default_context.integration["requestParameters"] = {
            "integration.request.path.path": "method.request.path.proxy",
        }
        default_context.integration["uri"] = "https://example.com/{path}/${stageVariables.stageVar}"
        integration_request_handler(default_context)
        assert default_context.integration_request["uri"] == "https://example.com/path/stageValue"


REQUEST_OVERRIDE = """
#set($context.requestOverride.header.header = "headerOverride")
#set($context.requestOverride.header.multivalue = ["1header", "2header"])
#set($context.requestOverride.path.path = "pathOverride")
#set($context.requestOverride.querystring.qs = "queryOverride")
"""
