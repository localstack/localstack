import json
from http import HTTPMethod

import pytest
from rolo import Request
from werkzeug.datastructures import Headers

from localstack.services.apigateway.next_gen.execute_api.context import (
    EndpointResponse,
    InvocationRequest,
    RestApiInvocationContext,
)
from localstack.services.apigateway.next_gen.execute_api.gateway_response import (
    Default4xxError,
    Default5xxError,
)
from localstack.services.apigateway.next_gen.execute_api.handlers import InvocationRequestParser
from localstack.services.apigateway.next_gen.execute_api.parameters_mapping import ParametersMapper
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
    ContextVarsIdentity,
)
from localstack.utils.strings import to_bytes

TEST_API_ID = "test-api"
TEST_API_STAGE = "stage"
TEST_IDENTITY_API_KEY = "random-api-key"
TEST_USER_AGENT = "test/user-agent"


@pytest.fixture
def default_context_variables() -> ContextVariables:
    return ContextVariables(
        resourceId="resource-id",
        apiId=TEST_API_ID,
        identity=ContextVarsIdentity(
            apiKey=TEST_IDENTITY_API_KEY,
            userAgent=TEST_USER_AGENT,
        ),
    )


@pytest.fixture
def default_invocation_request() -> InvocationRequest:
    context = RestApiInvocationContext(
        Request(
            method=HTTPMethod.POST,
            headers=Headers({"header_value": "test-header-value"}),
            path=f"{TEST_API_STAGE}/test/test-path-value",
            query_string="qs_value=test-qs-value",
        )
    )
    # Context populated by parser handler before creating the invocation request
    context.stage = TEST_API_STAGE
    context.api_id = TEST_API_ID

    invocation_request = InvocationRequestParser().create_invocation_request(context)
    invocation_request["path_parameters"] = {"path_value": "test-path-value"}
    return invocation_request


@pytest.fixture
def default_endpoint_response() -> EndpointResponse:
    return EndpointResponse(
        body=b"",
        headers=Headers(),
        status_code=200,
    )


class TestApigatewayRequestParametersMapping:
    def test_default_request_mapping(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.test": "method.request.querystring.qs_value",
            "integration.request.querystring.test": "method.request.path.path_value",
            "integration.request.path.test": "method.request.header.header_value",
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {
                "test": "test-qs-value",
            },
            "path": {"test": "test-header-value"},
            "querystring": {"test": "test-path-value"},
        }

    def test_context_variables(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.api_id": "context.apiId",
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {
                "api_id": TEST_API_ID,
            },
            "path": {},
            "querystring": {},
        }

    def test_nested_context_var(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.my_api_key": "context.identity.apiKey",
            "integration.request.querystring.userAgent": "context.identity.userAgent",
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {
                "my_api_key": TEST_IDENTITY_API_KEY,
            },
            "path": {},
            "querystring": {"userAgent": TEST_USER_AGENT},
        }

    def test_stage_variable_mapping(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.my_stage_var": "stageVariables.test_var",
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={"test_var": "a stage variable"},
        )

        assert mapping == {
            "header": {
                "my_stage_var": "a stage variable",
            },
            "path": {},
            "querystring": {},
        }

    def test_body_mapping(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.body_value": "method.request.body",
        }
        default_invocation_request["body"] = b"<This is a body value>"

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {
                "body_value": "<This is a body value>",
            },
            "path": {},
            "querystring": {},
        }

    def test_body_mapping_empty(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.body_value": "method.request.body",
        }
        default_invocation_request["body"] = b""

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )
        # this was validated against AWS
        # it does not forward the body even with passthrough, but the content of `method.request.body` is `{}`
        # if the body is empty
        assert mapping == {
            "header": {
                "body_value": "{}",
            },
            "path": {},
            "querystring": {},
        }

    def test_json_body_mapping(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.body_value": "method.request.body.petstore.pets[0].name",
        }

        default_invocation_request["body"] = to_bytes(
            json.dumps(
                {
                    "petstore": {
                        "pets": [
                            {"name": "nested pet name value", "type": "Dog"},
                            {"name": "second nested value", "type": "Cat"},
                        ]
                    }
                }
            )
        )

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {
                "body_value": "nested pet name value",
            },
            "path": {},
            "querystring": {},
        }

    def test_json_body_mapping_not_found(
        self, default_invocation_request, default_context_variables
    ):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.body_value": "method.request.body.petstore.pets[0].name",
        }

        default_invocation_request["body"] = to_bytes(
            json.dumps(
                {
                    "petstore": {
                        "pets": {
                            "name": "nested pet name value",
                            "type": "Dog",
                        }
                    }
                }
            )
        )

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {},
            "path": {},
            "querystring": {},
        }

    def test_invalid_json_body_mapping(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        # the only way AWS raises wrong JSON is if the body starts with `{`
        default_invocation_request["body"] = b"\n{wrongjson"

        request_parameters = {
            "integration.request.header.body_value": "method.request.body.petstore.pets[0].name",
        }

        with pytest.raises(Default4xxError) as e:
            mapper.map_integration_request(
                request_parameters=request_parameters,
                invocation_request=default_invocation_request,
                context_variables=default_context_variables,
                stage_variables={},
            )
        assert e.value.status_code == 400
        assert e.value.message == "Invalid JSON in request body"

        request_parameters = {
            "integration.request.header.body_value": "method.request.body",
        }

        # this is weird, but even if `method.request.body` should not expect JSON and can accept any string (as a
        # string is valid JSON per definition), it fails if it's malformed JSON.
        # maybe this is because the AWS console sends `Content-Type: application/json` by default?
        # TODO: write more AWS validated tests about this
        with pytest.raises(Default4xxError) as e:
            mapper.map_integration_request(
                request_parameters=request_parameters,
                invocation_request=default_invocation_request,
                context_variables=default_context_variables,
                stage_variables={},
            )

        assert e.value.status_code == 400
        assert e.value.message == "Invalid JSON in request body"

    def test_multi_headers_mapping(self, default_invocation_request, default_context_variables):
        # this behavior has been tested manually with the AWS console. TODO: write an AWS validated test
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.test": "method.request.header.testMultiHeader",
            "integration.request.header.test_multi": "method.request.multivalueheader.testMultiHeader",
            "integration.request.header.test_multi_solo": "method.request.multivalueheader.testHeader",
        }

        headers = {"testMultiHeader": ["value1", "value2"], "testHeader": "value"}

        default_invocation_request["headers"] = Headers(headers)
        # this is how AWS maps to the variables passed to proxy integration, it only picks the first of the multi values

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        # it seems the mapping picks the last value of the multivalues, but the `headers` part of the context picks the
        # first one
        assert mapping == {
            "header": {
                "test": "value2",
                "test_multi": "value1,value2",
                "test_multi_solo": "value",
            },
            "path": {},
            "querystring": {},
        }

    def test_multi_qs_mapping(self, default_invocation_request, default_context_variables):
        # this behavior has been tested manually with the AWS console. TODO: write an AWS validated test
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.querystring.test": "method.request.querystring.testMultiQuery",
            "integration.request.querystring.test_multi": "method.request.multivaluequerystring.testMultiQuery",
            "integration.request.querystring.test_multi_solo": "method.request.multivaluequerystring.testQuery",
        }

        default_invocation_request["query_string_parameters"] = {
            "testMultiQuery": "value1",
            "testQuery": "value",
        }
        default_invocation_request["multi_value_query_string_parameters"] = {
            "testMultiQuery": ["value1", "value2"],
            "testQuery": ["value"],
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        # it seems the mapping picks the last value of the multivalues, but the `headers` part of the context picks the
        # first one
        assert mapping == {
            "header": {},
            "path": {},
            "querystring": {
                "test": "value2",
                "test_multi": ["value1", "value2"],
                "test_multi_solo": "value",
            },
        }

    def test_default_request_mapping_missing_request_values(self, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.test": "method.request.querystring.qs_value",
            "integration.request.querystring.test": "method.request.path.path_value",
            "integration.request.path.test": "method.request.header.header_value",
        }

        request = InvocationRequest(
            headers=Headers(),
            query_string_parameters={},
            multi_value_query_string_parameters={},
            path_parameters={},
        )

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {},
            "path": {},
            "querystring": {},
        }

    def test_request_mapping_casing(self, default_invocation_request, default_context_variables):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.test": "method.request.querystring.QS_value",
            "integration.request.querystring.test": "method.request.path.PATH_value",
            "integration.request.path.test": "method.request.header.HEADER_value",
        }

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {},
            "path": {},
            "querystring": {},
        }

    def test_default_values_headers_request_mapping_override(
        self, default_invocation_request, default_context_variables
    ):
        mapper = ParametersMapper()
        request_parameters = {
            "integration.request.header.Content-Type": "method.request.header.header_value",
            "integration.request.header.accept": "method.request.header.header_value",
        }
        default_invocation_request["headers"].add("Content-Type", "application/json")
        default_invocation_request["headers"].add("Accept", "application/json")

        mapping = mapper.map_integration_request(
            request_parameters=request_parameters,
            invocation_request=default_invocation_request,
            context_variables=default_context_variables,
            stage_variables={},
        )
        assert mapping == {
            "header": {
                "Content-Type": "test-header-value",
                "accept": "test-header-value",
            },
            "path": {},
            "querystring": {},
        }


class TestApigatewayResponseParametersMapping:
    """
    Only `method.response` headers can be mapping from `responseParameters`.
    https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html#mapping-response-parameters
    """

    def test_default_request_mapping(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        # as the scope is more limited for ResponseParameters, we test header fetching, context variables and
        # stage variables in the same test, as it re-uses the same logic as the TestApigatewayRequestParametersMapping
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.method_test": "integration.response.header.test",
            "method.response.header.api_id": "context.apiId",
            "method.response.header.my_api_key": "context.identity.apiKey",
            "method.response.header.my_stage_var": "stageVariables.test_var",
            # missing value in the Response
            "method.response.header.missing_test": "integration.response.header.missingtest",
        }

        default_endpoint_response["headers"] = Headers({"test": "value"})

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={"test_var": "a stage variable"},
        )

        assert mapping == {
            "header": {
                "method_test": "value",
                "api_id": TEST_API_ID,
                "my_api_key": TEST_IDENTITY_API_KEY,
                "my_stage_var": "a stage variable",
            },
        }

    def test_body_mapping(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.body_value": "integration.response.body",
        }

        default_endpoint_response["body"] = b"<This is a body value>"

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {"body_value": "<This is a body value>"},
        }

    def test_body_mapping_empty(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.body_value": "integration.response.body",
        }

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        # this was validated against AWS
        assert mapping == {
            "header": {"body_value": "{}"},
        }

    def test_json_body_mapping(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.body_value": "integration.response.body.petstore.pets[0].name",
        }

        default_endpoint_response["body"] = to_bytes(
            json.dumps(
                {
                    "petstore": {
                        "pets": [
                            {"name": "nested pet name value", "type": "Dog"},
                            {"name": "second nested value", "type": "Cat"},
                        ]
                    }
                }
            )
        )

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {"body_value": "nested pet name value"},
        }

    def test_json_body_mapping_not_found(
        self, default_invocation_request, default_context_variables, default_endpoint_response
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.body_value": "integration.response.body.petstore.pets[0].name",
        }

        default_endpoint_response["body"] = to_bytes(
            json.dumps(
                {
                    "petstore": {
                        "pets": {
                            "name": "nested pet name value",
                            "type": "Dog",
                        }
                    }
                }
            )
        )

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {},
        }

    def test_invalid_json_body_mapping(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        # the only way AWS raises wrong JSON is if the body starts with `{`
        default_endpoint_response["body"] = b"\n{wrongjson"

        response_parameters = {
            "method.response.header.body_value": "integration.response.body.petstore.pets[0].name",
        }

        with pytest.raises(Default5xxError) as e:
            mapper.map_integration_response(
                response_parameters=response_parameters,
                integration_response=default_endpoint_response,
                context_variables=default_context_variables,
                stage_variables={},
            )
        assert e.value.status_code == 500
        assert e.value.message == "Internal server error"

        response_parameters = {
            "method.response.header.body_value": "integration.response.body",
        }

        with pytest.raises(Default5xxError) as e:
            mapper.map_integration_response(
                response_parameters=response_parameters,
                integration_response=default_endpoint_response,
                context_variables=default_context_variables,
                stage_variables={},
            )

        assert e.value.status_code == 500
        assert e.value.message == "Internal server error"

    def test_multi_headers_mapping(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.test": "integration.response.header.testMultiHeader",
            "method.response.header.test_multi": "integration.response.multivalueheader.testMultiHeader",
            "method.response.header.test_multi_solo": "integration.response.multivalueheader.testHeader",
        }
        default_endpoint_response["headers"] = Headers(
            {
                "testMultiHeader": ["value1", "value2"],
                "testHeader": "value",
            }
        )

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        # it seems the mapping picks the last value of the multivalues, but the `headers` part of the context picks the
        # first one
        assert mapping == {
            "header": {"test": "value2", "test_multi": "value1,value2", "test_multi_solo": "value"},
        }

    def test_response_mapping_casing(
        self, default_invocation_request, default_endpoint_response, default_context_variables
    ):
        mapper = ParametersMapper()
        response_parameters = {
            "method.response.header.test": "integration.response.header.test",
            "method.response.header.test2": "integration.response.header.TEST2",
            "method.response.header.testmulti": "integration.response.multivalueheader.testmulti",
        }
        default_endpoint_response["headers"] = Headers(
            {
                "Test": "test",
                "test2": "test",
                "TestMulti": ["test", "test2"],
            }
        )

        mapping = mapper.map_integration_response(
            response_parameters=response_parameters,
            integration_response=default_endpoint_response,
            context_variables=default_context_variables,
            stage_variables={},
        )

        assert mapping == {
            "header": {},
        }
