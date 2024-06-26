import json

import pytest

from localstack.aws.api.apigateway import Method, Model, RequestValidator, RestApi
from localstack.http import Request, Response
from localstack.services.apigateway.models import MergedRestApi, RestApiDeployment
from localstack.services.apigateway.next_gen.execute_api.api import RestApiGatewayHandlerChain
from localstack.services.apigateway.next_gen.execute_api.context import (
    InvocationRequest,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    BadRequestBodyError,
    BadRequestParametersError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import MethodRequestHandler
from localstack.testing.config import TEST_AWS_ACCOUNT_ID, TEST_AWS_REGION_NAME


@pytest.fixture
def method_request_handler():
    """Returns a dummy request handler invoker for testing."""

    def _handler_invoker(context: RestApiInvocationContext):
        return MethodRequestHandler()(RestApiGatewayHandlerChain(), context, Response())

    return _handler_invoker


@pytest.fixture
def dummy_context():
    context = RestApiInvocationContext(Request())
    context.deployment = RestApiDeployment(
        TEST_AWS_ACCOUNT_ID,
        TEST_AWS_REGION_NAME,
        rest_api=MergedRestApi(rest_api=RestApi()),
    )
    context.resource_method = Method()
    return context


class TestMethodRequestHandler:
    def test_no_validator(self, method_request_handler, dummy_context):
        method_request_handler(dummy_context)

    def test_validator_no_validation_required(self, method_request_handler, dummy_context):
        validator_id = "validatorId"
        validator = RequestValidator(id=validator_id, validateRequestParameters=False)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id,
            requestParameters={
                "method.request.querystring.foo": True,
                "method.request.header.foo": True,
            },
        )
        method_request_handler(dummy_context)

    def test_validator_no_params_to_validate(self, method_request_handler, dummy_context):
        validator_id = "validatorId"
        validator = RequestValidator(id=validator_id, validateRequestParameters=False)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id,
            requestParameters={
                "method.request.querystring.foo": False,
                "method.request.header.foo": False,
            },
        )
        method_request_handler(dummy_context)

    def test_validator_request_parameters(self, method_request_handler, dummy_context):
        validator_id = "validatorId"
        validator = RequestValidator(id=validator_id, validateRequestParameters=True)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id,
            requestParameters={
                "method.request.querystring.query": True,
                "method.request.header.x-header": True,
                "method.request.path.proxy": True,
            },
        )

        # Invocation with no valid element
        dummy_context.invocation_request = InvocationRequest(
            headers={}, query_string_parameters={}, path=""
        )
        with pytest.raises(BadRequestParametersError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Missing required request parameters: [x-header, proxy, query]"

        # invocation with valid header
        dummy_context.invocation_request["headers"]["x-header"] = "foobar"
        with pytest.raises(BadRequestParametersError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Missing required request parameters: [proxy, query]"

        # invocation with valid header and querystring
        dummy_context.invocation_request["query_string_parameters"]["query"] = "result"
        with pytest.raises(BadRequestParametersError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Missing required request parameters: [proxy]"

        # invocation with valid request
        dummy_context.invocation_request["path"] = "/proxy/path"
        method_request_handler(dummy_context)

    def test_validator_request_body_empty_model(self, method_request_handler, dummy_context):
        validator_id = "validatorId"
        model_id = "model_id"
        validator = RequestValidator(id=validator_id, validateRequestBody=True)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.deployment.rest_api.models = {
            model_id: Model(
                id=model_id,
                name=model_id,
                schema=json.dumps({"$schema": "http://json-schema.org/draft-04/schema#"}),
                contentType="application/json",
            )
        }
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id, requestModels={"application/json": model_id}
        )

        # Invocation with no body
        dummy_context.invocation_request = InvocationRequest(body=b"{}")
        method_request_handler(dummy_context)

        # Invocation with a body
        dummy_context.invocation_request = InvocationRequest(body=b'{"foo": "bar"}')
        method_request_handler(dummy_context)

    def test_validator_validate_body_with_schema(self, method_request_handler, dummy_context):
        validator_id = "validatorId"
        model_id = "model_id"
        validator = RequestValidator(id=validator_id, validateRequestBody=True)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.deployment.rest_api.models = {
            model_id: Model(
                id=model_id,
                name=model_id,
                schema=json.dumps(
                    {"$schema": "http://json-schema.org/draft-04/schema#", "required": ["foo"]}
                ),
                contentType="application/json",
            )
        }
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id, requestModels={"application/json": model_id}
        )

        # Invocation with no body
        dummy_context.invocation_request = InvocationRequest(body=b"{}")
        with pytest.raises(BadRequestBodyError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Invalid request body"

        # Invocation with an invalid body
        dummy_context.invocation_request = InvocationRequest(body=b'{"not": "foo"}')
        with pytest.raises(BadRequestBodyError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Invalid request body"

        # Invocation with a valid body
        dummy_context.invocation_request = InvocationRequest(body=b'{"foo": "bar"}')
        method_request_handler(dummy_context)

    def test_validator_validate_body_with_no_model_for_schema_name(
        self, method_request_handler, dummy_context
    ):
        # TODO verify this is required as it might not be a possible scenario on aws
        validator_id = "validatorId"
        model_id = "model_id"
        validator = RequestValidator(id=validator_id, validateRequestBody=True)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id, requestModels={"application/json": model_id}
        )

        dummy_context.invocation_request = InvocationRequest(body=b"{}")
        with pytest.raises(BadRequestBodyError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Invalid request body"

    def test_validate_body_with_circular_and_recursive_model(
        self, method_request_handler, dummy_context
    ):
        validator_id = "validatorId"
        model_1 = "Person"
        model_2 = "House"
        validator = RequestValidator(id=validator_id, validateRequestBody=True)
        dummy_context.deployment.rest_api.validators = {validator_id: validator}
        dummy_context.deployment.rest_api.models = {
            # set up the model, Person, which references House
            model_1: Model(
                id=model_1,
                name=model_1,
                schema=json.dumps(
                    {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string",
                            },
                            "house": {
                                "$ref": "House",
                            },
                        },
                        "required": ["name"],
                    }
                ),
                contentType="application/json",
            ),
            # set up the model House, which references the Person model, we have a circular ref, and House itself
            model_2: Model(
                id=model_2,
                name=model_2,
                schema=json.dumps(
                    {
                        "type": "object",
                        "required": ["houseType"],
                        "properties": {
                            "houseType": {
                                "type": "string",
                            },
                            "contains": {
                                "type": "array",
                                "items": {
                                    "$ref": "Person",
                                },
                            },
                            "houses": {
                                "type": "array",
                                "items": {
                                    "$ref": "/House",
                                },
                            },
                        },
                    }
                ),
                contentType="application/json",
            ),
        }
        dummy_context.resource_method = Method(
            requestValidatorId=validator_id, requestModels={"application/json": model_1}
        )

        # Invalid body
        dummy_context.invocation_request = InvocationRequest(
            body=json.dumps(
                {
                    "name": "test",
                    "house": {  # the House object is missing "houseType"
                        "contains": [{"name": "test"}],  # the Person object has the required "name"
                        "houses": [{"coucou": "test"}],  # the House object is missing "houseType"
                    },
                }
            ).encode()
        )
        with pytest.raises(BadRequestBodyError) as e:
            method_request_handler(dummy_context)
        assert e.value.message == "Invalid request body"

        # Valid body
        dummy_context.invocation_request = InvocationRequest(
            body=json.dumps(
                {
                    "name": "test",
                    "house": {
                        "houseType": "random",  # the House object has the required ""houseType"
                        "contains": [{"name": "test"}],  # the Person object has the required "name"
                        "houses": [
                            {"houseType": "test"}  # the House object has the required "houseType"
                        ],
                    },
                }
            ).encode()
        )
        method_request_handler(dummy_context)
