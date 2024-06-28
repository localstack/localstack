import pytest
from moto.apigateway.models import APIGatewayBackend, apigateway_backends
from werkzeug.datastructures.headers import Headers

from localstack.aws.api.apigateway import ApiKeySourceType, Method
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    ContextVariables,
    IdentityContext,
    InvocationRequest,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import InvalidAPIKeyError
from localstack.services.apigateway.next_gen.execute_api.handlers import ApiKeyValidationHandler
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME

TEST_API_ID = "testapi"
TEST_API_STAGE = "dev"


@pytest.fixture
def moto_backend():
    """
    because we depend on Moto here, we have to use the backend because the keys and usage plans
    are fetched at runtime in the store directly. We should avoid using this fixture directly in
    the tests and favor reusable fixture that could later on be replaced to populate the Localstack
    store instead without impacting the tests
    """
    moto_backend: APIGatewayBackend = apigateway_backends[TEST_AWS_ACCOUNT_ID][TEST_AWS_REGION_NAME]
    yield moto_backend
    moto_backend.reset()


@pytest.fixture
def create_context():
    """
    Create a context populated with what we would expect to receive from the chain at runtime.
    We assume that the parser and other handler have successfully populated the context to this point.
    """

    def _create_context(
        method: Method = None,
        api_key_source: ApiKeySourceType = None,
        headers: dict[str, str] = None,
        api_key: str = None,
    ):
        context = RestApiInvocationContext(Request())

        # The api key validator only relies on the raw headers from the invocation requests
        context.invocation_request = InvocationRequest(raw_headers=Headers(headers))

        # Frozen deployment populated by the router
        context.deployment = RestApiDeployment(
            account_id=TEST_AWS_ACCOUNT_ID,
            region=TEST_AWS_REGION_NAME,
            rest_api=MergedRestApi(
                # TODO validate that this value is always populated by localstack. AWS defaults to HEADERS on all new apis
                rest_api={"apiKeySource": api_key_source or ApiKeySourceType.HEADER}
            ),
        )

        # Context populated by parser handler
        context.region = TEST_AWS_REGION_NAME
        context.account_id = TEST_AWS_ACCOUNT_ID
        context.stage = TEST_API_STAGE
        context.api_id = TEST_API_ID
        context.resource_method = method or Method()
        context.context_variables = ContextVariables()

        # Context populated by a Lambda Authorizer
        if api_key is not None:
            context.context_variables["identity"] = IdentityContext(apiKey=api_key)
        return context

    return _create_context


@pytest.fixture
def api_key_validation_handler():
    """Returns a dummy api key validation handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext):
        return ApiKeyValidationHandler()(RestApiGatewayHandlerChain(), context, Response())

    return _handler_invoker


@pytest.fixture
def create_usage_plan(moto_backend):
    def _create_usage_plan(attach_stage: bool, attach_key_id: str = None, backend=None):
        backend = backend or moto_backend
        stage_config = {}
        if attach_stage:
            stage_config = {"apiStages": [{"apiId": TEST_API_ID, "stage": TEST_API_STAGE}]}
        usage_plan = backend.create_usage_plan(stage_config)
        if attach_key_id:
            backend.create_usage_plan_key(
                usage_plan_id=usage_plan.id, payload={"keyId": attach_key_id, "keyType": "API_KEY"}
            )
        return usage_plan

    return _create_usage_plan


@pytest.fixture
def create_api_key(moto_backend):
    def _create_api_key(key_value: str, enabled: bool = True, backend=None):
        backend = backend or moto_backend
        return backend.create_api_key({"enabled": enabled, "value": key_value})

    return _create_api_key


class TestHandlerApiKeyValidation:
    def test_no_api_key_required(self, create_context, api_key_validation_handler):
        api_key_validation_handler(create_context())

    def test_api_key_headers_valid(
        self, create_context, api_key_validation_handler, create_usage_plan, create_api_key
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # create api key
        api_key = create_api_key(api_key_value)
        # create usage plan and attach key
        create_usage_plan(attach_stage=True, attach_key_id=api_key.id)
        # pass the key in the request headers
        ctx = create_context(method=method, headers={"x-api-key": api_key_value})

        # Call handler
        api_key_validation_handler(context=ctx)

        assert ctx.context_variables["identity"]["apiKey"] == api_key_value
        assert ctx.context_variables["identity"]["apiKeyId"] == api_key.id

    def test_api_key_headers_absent(
        self, create_context, api_key_validation_handler, create_api_key, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # create api key
        api_key = create_api_key(api_key_value)
        # create usage plan and attach key
        create_usage_plan(attach_stage=True, attach_key_id=api_key.id)

        with pytest.raises(InvalidAPIKeyError) as e:
            api_key_validation_handler(
                # missing headers will raise error
                context=create_context(method=method, headers={})
            )
        assert e.value.message == "Forbidden"

    def test_api_key_no_api_key(
        self, create_context, api_key_validation_handler, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # Create usage plan with no keys
        create_usage_plan(attach_stage=True)

        with pytest.raises(InvalidAPIKeyError) as e:
            api_key_validation_handler(
                context=create_context(method=method, headers={"x-api-key": api_key_value})
            )
        assert e.value.message == "Forbidden"

    def test_api_key_no_usage_plan_key(
        self, create_context, api_key_validation_handler, create_api_key, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # create api key
        create_api_key(api_key_value)
        # Create usage plan but the key won't be associated
        create_usage_plan(attach_stage=True)

        with pytest.raises(InvalidAPIKeyError) as e:
            api_key_validation_handler(
                context=create_context(method=method, headers={"x-api-key": api_key_value})
            )
        assert e.value.message == "Forbidden"

    def test_api_key_disabled(
        self, create_context, api_key_validation_handler, create_api_key, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # Create api key but set `Enabled` to False
        api_key = create_api_key(api_key_value, enabled=False)
        # create usage plan and attach key
        create_usage_plan(attach_stage=True, attach_key_id=api_key.id)

        with pytest.raises(InvalidAPIKeyError) as e:
            api_key_validation_handler(
                context=create_context(method=method, headers={"x-api-key": api_key_value})
            )
        assert e.value.message == "Forbidden"

    def test_api_key_in_identity_context(
        self, create_context, api_key_validation_handler, create_api_key, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # create api key
        api_key = create_api_key(api_key_value)
        # create usage plan and attach key
        create_usage_plan(attach_stage=True, attach_key_id=api_key.id)

        api_key_validation_handler(
            context=create_context(
                # The frozen api has key source set to AUTHORIZER and the api_key was populated by the Authorizer
                method=method,
                api_key=api_key_value,
                api_key_source=ApiKeySourceType.AUTHORIZER,
            )
        )

    def test_api_key_in_identity_context_api_not_configured(
        self, create_context, api_key_validation_handler, create_api_key, create_usage_plan
    ):
        method = Method(apiKeyRequired=True)
        api_key_value = "01234567890123456789"

        # create api key
        api_key = create_api_key(api_key_value)
        # create usage plan and attach key
        create_usage_plan(attach_stage=True, attach_key_id=api_key.id)

        with pytest.raises(InvalidAPIKeyError) as e:
            # The api_key was populated by the Authorizer, but missing frozen api configuration
            api_key_validation_handler(context=create_context(method=method, api_key=api_key_value))
        assert e.value.message == "Forbidden"
