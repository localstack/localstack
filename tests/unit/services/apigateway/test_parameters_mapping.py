import json
from http import HTTPMethod

import pytest
from werkzeug.datastructures import Headers

from localstack.services.apigateway.next_gen.execute_api.context import InvocationRequest
from localstack.services.apigateway.next_gen.execute_api.gateway_response import Default4xxError
from localstack.services.apigateway.next_gen.execute_api.parameters_mapping import ParametersMapper
from localstack.services.apigateway.next_gen.execute_api.variables import (
    ContextVariables,
    ContextVarsIdentity,
)
from localstack.utils.strings import to_bytes

TEST_API_ID = "test-api"
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
    headers = {"header_value": "test-header-value"}
    return InvocationRequest(
        http_method=HTTPMethod.POST,
        raw_path="/test/test-path-value",
        path="/test/test-path-value",
        path_parameters={"path_value": "test-path-value"},
        query_string_parameters={"qs_value": "test-qs-value"},
        raw_headers=Headers(headers),
        headers=headers,
        multi_value_query_string_parameters={"qs_value": ["test-qs-value"]},
        multi_value_headers={"header_value": ["test-header-value"]},
        body=b"",
    )


class TestApigatewayParametersMapping:
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

        print(f"{default_invocation_request=}")

        assert mapping == {
            "header": {"test": "test-qs-value"},
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
            "header": {"api_id": TEST_API_ID},
            "path": {},
            "querystring": {},
        }

    def test_nested_context_var(self, default_invocation_request, default_context_variables):
        # TODO: test in AWS casing of context variables??
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
            "header": {"my_api_key": TEST_IDENTITY_API_KEY},
            "path": {},
            "querystring": {"userAgent": TEST_USER_AGENT},
        }

    def test_stage_variable_mapping(self, default_invocation_request, default_context_variables):
        # TODO: test in AWS casing of stage Variables??
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
            "header": {"my_stage_var": "a stage variable"},
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
            "header": {"body_value": "<This is a body value>"},
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
            "header": {"body_value": "{}"},
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
            "header": {"body_value": "nested pet name value"},
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

        default_invocation_request["raw_headers"] = Headers(headers)
        # this is how AWS maps to the variables passed to proxy integration, it only picks the first of the multi values
        default_invocation_request["headers"] = {"testMultiHeader": "value1", "testHeader": "value"}

        default_invocation_request["multi_value_headers"] = {
            "testMultiHeader": ["value1", "value2"],
            "testHeader": ["value"],
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
            "header": {"test": "value2", "test_multi": "value1,value2", "test_multi_solo": "value"},
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
            raw_headers=Headers(),
            headers={},
            multi_value_headers={},
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
