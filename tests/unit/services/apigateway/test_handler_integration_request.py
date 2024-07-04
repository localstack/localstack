from http import HTTPMethod

import pytest

from localstack.aws.api.apigateway import Integration, IntegrationType, Method
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    InvocationRequest,
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
    ContextVarsRequestOverride,
)
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

TEST_API_ID = "test-api"
TEST_API_STAGE = "stage"


@pytest.fixture
def create_context():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    def _create_context(
        method: Method = None,
        request: InvocationRequest = None,
    ):
        context = RestApiInvocationContext(Request())

        # The api key validator only relies on the raw headers from the invocation requests
        context.invocation_request = request or InvocationRequest()

        # Frozen deployment populated by the router
        context.deployment = RestApiDeployment(
            account_id=TEST_AWS_ACCOUNT_ID,
            region=TEST_AWS_REGION_NAME,
            rest_api=MergedRestApi(rest_api={}),
        )

        # Context populated by parser handler
        context.region = TEST_AWS_REGION_NAME
        context.account_id = TEST_AWS_ACCOUNT_ID
        context.stage = TEST_API_STAGE
        context.api_id = TEST_API_ID
        context.resource_method = method or Method(
            methodIntegration=Integration(
                type=IntegrationType.HTTP,
                requestParameters=None,
                uri="https://example.com",
                httpMethod="POST",
            )
        )
        context.context_variables = ContextVariables(
            resourceId="resource-id",
            apiId=TEST_API_ID,
            httpMethod="POST",
            path=f"{TEST_API_STAGE}/resource/{{proxy}}",
            requestOverride=ContextVarsRequestOverride(header={}, path={}, querystring={}),
            resourcePath="/resource/{proxy}",
            stage=TEST_API_STAGE,
        )

        return context

    return _create_context


@pytest.fixture
def default_invocation_request() -> InvocationRequest:
    request = InvocationRequestParser().create_invocation_request(
        Request(
            method=HTTPMethod.POST,
            headers={"header": ["header1", "header2"]},
            path=f"{TEST_API_STAGE}/resource/path",
            query_string="qs=qs1&qs=qs2",
        )
    )
    request["path_parameters"] = {"proxy": "path"}
    return request


@pytest.fixture
def integration_request_handler():
    """Returns a dummy integration request handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext):
        return IntegrationRequestHandler()(RestApiGatewayHandlerChain(), context, Response())

    return _handler_invoker


class TestHandlerIntegrationRequest:
    def test_noop(self, integration_request_handler, default_invocation_request, create_context):
        context = create_context(request=default_invocation_request)
        integration_request_handler(context)
        assert context.integration_request == {
            "body": b"",
            "headers": {},
            "http_method": "POST",
            "query_string_parameters": {},
            "uri": "https://example.com",
        }

    def test_passthrough_never(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["passthroughBehavior"] = (
            PassthroughBehavior.NEVER
        )

        # With no template, it is expected to raise
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(context)
        assert e.match("Unsupported Media Type")

        # With a non-matching template it should raise
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/xml": "#Empty"
        }
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(context)
        assert e.match("Unsupported Media Type")

        # With a matching template it should use it
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/json": '{"foo":"bar"}'
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b'{"foo":"bar"}'

    def test_passthrough_when_no_match(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["passthroughBehavior"] = (
            PassthroughBehavior.WHEN_NO_MATCH
        )
        # When no template are created it should passthrough
        integration_request_handler(context)
        assert context.integration_request["body"] == b""

        # when a non matching template is found it should passthrough
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/xml": '{"foo":"bar"}'
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b""

        # when a matching template is found, it should use it
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/json": '{"foo":"bar"}'
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b'{"foo":"bar"}'

    def test_passthrough_when_no_templates(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["passthroughBehavior"] = (
            PassthroughBehavior.WHEN_NO_TEMPLATES
        )
        # If a non matching template is found, it should raise
        context.resource_method["methodIntegration"]["requestTemplates"] = {"application/xml": ""}
        with pytest.raises(UnsupportedMediaTypeError) as e:
            integration_request_handler(context)
        assert e.match("Unsupported Media Type")

        # If a matching template is found, it should use it
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/json": '{"foo":"bar"}'
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b'{"foo":"bar"}'

        # If no template were created, it should passthrough
        context.resource_method["methodIntegration"]["requestTemplates"] = {}
        integration_request_handler(context)
        assert context.integration_request["body"] == b""

    def test_default_template(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        request = default_invocation_request
        context = create_context(request=request)

        # if no matching template, use the default
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "$default": '{"foo":"bar"}'
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b'{"foo":"bar"}'

        # If there is a matching template, use it instead
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "$default": '{"foo":"bar"}',
            "application/json": "Matching Template",
        }
        integration_request_handler(context)
        assert context.integration_request["body"] == b"Matching Template"

    def test_request_parameters(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["requestParameters"] = {
            "integration.request.path.path": "method.request.path.path",
            "integration.request.querystring.qs": "method.request.querystring.qs",
            "integration.request.header.header": "method.request.header.header",
        }
        context.resource_method["methodIntegration"]["uri"] = "https://example.com/{path}"
        integration_request_handler(context)
        # TODO this test will fail when we implement uri mapping
        assert context.integration_request["uri"] == "https://example.com/{path}"
        assert context.integration_request["query_string_parameters"] == {"qs": "qs2"}
        assert context.integration_request["headers"] == {"header": "header2"}

    def test_request_override(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["requestParameters"] = {
            "integration.request.path.path": "method.request.path.path",
            "integration.request.querystring.qs": "method.request.multivaluequerystring.qs",
            "integration.request.header.header": "method.request.header.header",
        }
        context.resource_method["methodIntegration"]["uri"] = "https://example.com/{path}"
        context.resource_method["methodIntegration"]["requestTemplates"] = {
            "application/json": REQUEST_OVERRIDE
        }
        integration_request_handler(context)
        # TODO this test will fail when we implement uri mapping
        assert context.integration_request["uri"] == "https://example.com/{path}"
        assert context.integration_request["query_string_parameters"] == {"qs": "queryOverride"}
        assert context.integration_request["headers"] == {
            "header": "headerOverride",
            "multivalue": ["1header", "2header"],
        }

    def test_multivalue_mapping(
        self, integration_request_handler, default_invocation_request, create_context
    ):
        context = create_context(request=default_invocation_request)
        context.resource_method["methodIntegration"]["requestParameters"] = {
            "integration.request.header.multi": "method.request.multivalueheader.header",
            "integration.request.querystring.multi": "method.request.multivaluequerystring.qs",
        }
        integration_request_handler(context)
        assert context.integration_request["headers"]["multi"] == "header1,header2"
        assert context.integration_request["query_string_parameters"]["multi"] == ["qs1", "qs2"]


REQUEST_OVERRIDE = """
#set($context.requestOverride.header.header = "headerOverride")
#set($context.requestOverride.header.multivalue = ["1header", "2header"])
#set($context.requestOverride.path.path = "pathOverride")
#set($context.requestOverride.querystring.qs = "queryOverride")
"""
