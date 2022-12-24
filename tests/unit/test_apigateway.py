import json
import os
import unittest
from unittest.mock import Mock

import boto3
import pytest

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway.helpers import (
    Resolver,
    apply_json_patch_safe,
    create_invocation_headers,
    extract_path_params,
    extract_query_string_params,
    get_resource_for_path,
)
from localstack.services.apigateway.integration import LambdaProxyIntegration
from localstack.services.apigateway.invocations import (
    ApiInvocationContext,
    RequestValidator,
    apply_request_parameters,
)
from localstack.services.apigateway.templates import (
    RequestTemplates,
    ResponseTemplates,
    VelocityUtilApiGateway,
)
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.common import clone
from localstack.utils.files import load_file


def load_test_resource(file_name: str, file_path: str = None) -> str:
    if file_path:
        return load_file(os.path.join(os.path.dirname(__file__), file_path, file_name))
    return load_file(os.path.join(os.path.dirname(__file__), "./templates", file_name))


class ApiGatewayPathsTest(unittest.TestCase):
    def test_extract_query_params(self):
        path, query_params = extract_query_string_params("/foo/bar?foo=foo&bar=bar&bar=baz")
        self.assertEqual("/foo/bar", path)
        self.assertEqual({"foo": "foo", "bar": ["bar", "baz"]}, query_params)

    def test_extract_path_params(self):
        params = extract_path_params("/foo/bar", "/foo/{param1}")
        self.assertEqual({"param1": "bar"}, params)

        params = extract_path_params("/foo/bar1/bar2", "/foo/{param1}/{param2}")
        self.assertEqual({"param1": "bar1", "param2": "bar2"}, params)

        params = extract_path_params("/foo/bar", "/foo/bar")
        self.assertEqual({}, params)

        params = extract_path_params("/foo/bar/baz", "/foo/{proxy+}")
        self.assertEqual({"proxy": "bar/baz"}, params)

    def test_path_matches(self):
        path, details = get_resource_for_path("/foo/bar", {"/foo/{param1}": {}})
        self.assertEqual("/foo/{param1}", path)

        path, details = get_resource_for_path("/foo/bar", {"/foo/bar": {}, "/foo/{param1}": {}})
        self.assertEqual("/foo/bar", path)

        path, details = get_resource_for_path("/foo/bar/baz", {"/foo/bar": {}, "/foo/{proxy+}": {}})
        self.assertEqual("/foo/{proxy+}", path)

        path, details = get_resource_for_path(
            "/foo/bar/baz", {"/{proxy+}": {}, "/foo/{proxy+}": {}}
        )
        self.assertEqual("/foo/{proxy+}", path)

        result = get_resource_for_path("/foo/bar", {"/foo/bar1": {}, "/foo/bar2": {}})
        self.assertEqual(None, result)

        result = get_resource_for_path("/foo/bar", {"/{param1}/bar1": {}, "/foo/bar2": {}})
        self.assertEqual(None, result)

        path_args = {"/{param1}/{param2}/foo/{param3}": {}, "/{param}/bar": {}}
        path, details = get_resource_for_path("/foo/bar", path_args)
        self.assertEqual("/{param}/bar", path)

        path_args = {"/{param1}/{param2}": {}, "/{param}/bar": {}}
        path, details = get_resource_for_path("/foo/bar", path_args)
        self.assertEqual("/{param}/bar", path)

        path_args = {"/{param1}/{param2}": {}, "/{param1}/bar": {}}
        path, details = get_resource_for_path("/foo/baz", path_args)
        self.assertEqual("/{param1}/{param2}", path)

        path_args = {"/{param1}/{param2}/baz": {}, "/{param1}/bar/{param2}": {}}
        path, details = get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual("/{param1}/{param2}/baz", path)

        path_args = {"/{param1}/{param2}/baz": {}, "/{param1}/{param2}/{param2}": {}}
        path, details = get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual("/{param1}/{param2}/baz", path)

        path_args = {"/foo123/{param1}/baz": {}}
        result = get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual(None, result)

        path_args = {"/foo/{param1}/baz": {}, "/foo/{param1}/{param2}": {}}
        path, result = get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual("/foo/{param1}/baz", path)

    def test_apply_request_parameters(self):
        integration = {
            "type": "HTTP_PROXY",
            "httpMethod": "ANY",
            "uri": "https://httpbin.org/anything/{proxy}",
            "requestParameters": {"integration.request.path.proxy": "method.request.path.proxy"},
            "passthroughBehavior": "WHEN_NO_MATCH",
            "timeoutInMillis": 29000,
            "cacheNamespace": "041fa782",
            "cacheKeyParameters": [],
        }

        uri = apply_request_parameters(
            uri="https://httpbin.org/anything/{proxy}",
            integration=integration,
            path_params={"proxy": "foo/bar/baz"},
            query_params={"param": "foobar"},
        )
        self.assertEqual("https://httpbin.org/anything/foo/bar/baz?param=foobar", uri)

    def test_if_request_is_valid_with_no_resource_methods(self):
        ctx = ApiInvocationContext("POST", "/", b"", {})
        validator = RequestValidator(ctx, None)
        self.assertTrue(validator.is_request_valid())

    def test_if_request_is_valid_with_no_matching_method(self):
        ctx = ApiInvocationContext("POST", "/", b"", {})
        ctx.resource = {"resourceMethods": {"GET": {}}}
        validator = RequestValidator(ctx, None)
        self.assertTrue(validator.is_request_valid())

    def test_if_request_is_valid_with_no_validator(self):
        ctx = ApiInvocationContext("POST", "/", b"", {})
        ctx.api_id = "deadbeef"
        ctx.resource = {"resourceMethods": {"POST": {"requestValidatorId": " "}}}
        validator = RequestValidator(ctx, None)
        self.assertTrue(validator.is_request_valid())

    def test_if_request_has_body_validator(self):
        apigateway_client = self._mock_client()
        apigateway_client.get_request_validator.return_value = {"validateRequestBody": True}
        apigateway_client.get_model.return_value = {"schema": '{"type": "object"}'}
        ctx = ApiInvocationContext("POST", "/", '{"id":"1"}', {})
        ctx.api_id = "deadbeef"
        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": "112233",
                    "requestModels": {"application/json": "schemaName"},
                }
            }
        }
        validator = RequestValidator(ctx, apigateway_client)
        self.assertTrue(validator.is_request_valid())

    def test_request_validate_body_with_no_request_model(self):
        apigateway_client = self._mock_client()
        apigateway_client.get_request_validator.return_value = {"validateRequestBody": True}
        ctx = ApiInvocationContext("POST", "/", '{"id":"1"}', {})
        ctx.api_id = "deadbeef"
        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": "112233",
                    "requestModels": None,
                }
            }
        }
        validator = RequestValidator(ctx, apigateway_client)
        self.assertFalse(validator.is_request_valid())

    def test_request_validate_body_with_no_model_for_schema_name(self):
        apigateway_client = self._mock_client()
        apigateway_client.get_request_validator.return_value = {"validateRequestBody": True}
        apigateway_client.get_model.return_value = None
        ctx = ApiInvocationContext("POST", "/", '{"id":"1"}', {})
        ctx.api_id = "deadbeef"
        ctx.resource = {
            "resourceMethods": {
                "POST": {
                    "requestValidatorId": "112233",
                    "requestModels": {"application/json": "schemaName"},
                }
            }
        }
        validator = RequestValidator(ctx, apigateway_client)
        self.assertFalse(validator.is_request_valid())

    def _mock_client(self):
        return Mock(boto3.client("apigateway", region_name=config.AWS_REGION_US_EAST_1))


def test_render_template_values():
    util = VelocityUtilApiGateway()

    encoded = util.urlEncode("x=a+b")
    assert encoded == "x%3Da%2Bb"

    decoded = util.urlDecode("x=a+b")
    assert decoded == "x=a b"

    escape_tests = (
        ("it's", "it's"),
        ("0010", "0010"),
        ("true", "true"),
        ("True", "True"),
        ("1.021", "1.021"),
        ('""', '\\"\\"'),
        ('"""', '\\"\\"\\"'),
        ('{"foo": 123}', '{\\"foo\\": 123}'),
        ('{"foo"": 123}', '{\\"foo\\"\\": 123}'),
        (1, "1"),
        (None, "null"),
    )
    for string, expected in escape_tests:
        escaped = util.escapeJavaScript(string)
        assert escaped == expected


class TestJSONPatch(unittest.TestCase):
    def test_apply_json_patch(self):
        apply = apply_json_patch_safe

        # test replacing array index
        subject = {"root": [{"arr": ["1", "abc"]}]}
        result = apply(clone(subject), {"op": "replace", "path": "/root/0/arr/0", "value": 2})
        self.assertEqual({"arr": [2, "abc"]}, result["root"][0])

        # test replacing endpoint config type
        operation = {"op": "replace", "path": "/endpointConfiguration/types/0", "value": "EDGE"}
        subject = {
            "id": "b5d563g3yx",
            "endpointConfiguration": {"types": ["REGIONAL"], "vpcEndpointIds": []},
        }
        result = apply(clone(subject), operation)
        self.assertEqual(["EDGE"], result["endpointConfiguration"]["types"])

        # test replacing endpoint config type
        operation = {"op": "add", "path": "/features/-", "value": "feat2"}
        subject = {"features": ["feat1"]}
        result = apply(clone(subject), operation)
        self.assertEqual(["feat1", "feat2"], result["features"])


class TestApplyTemplate(unittest.TestCase):
    def test_apply_template(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data='{"action":"$default","message":"foobar"}',
            headers={"content-type": APPLICATION_JSON},
            stage="local",
        )
        api_context.response = requests_response({})
        api_context.integration = {
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }

        rendered_request = RequestTemplates().render(api_context=api_context)

        self.assertEqual('\\"foobar\\"', rendered_request)

    def test_apply_template_no_json_payload(self):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b'"#foobar123"',
            headers={"content-type": APPLICATION_JSON},
            stage="local",
        )
        api_context.integration = {
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }

        rendered_request = RequestTemplates().render(api_context=api_context)

        self.assertEqual("[]", rendered_request)


RESPONSE_TEMPLATE = """

#set( $body = $input.json("$") )
#define( $loop )
{
    #foreach($e in $map.keySet())
       #set( $k = $e )
       #set( $v = $map.get($k))
       "$k": "$v"
       #if( $foreach.hasNext ) , #end
    #end
}
#end
  {
    "body": $body,
    "method": "$context.httpMethod",
    "principalId": "$context.authorizer.principalId",
    "stage": "$context.stage",
    "cognitoPoolClaims" : {
       "sub": "$context.authorizer.claims.sub"
    },
    #set( $map = $context.authorizer )
    "enhancedAuthContext": $loop,

    #set( $map = $input.params().header )
    "headers": $loop,

    #set( $map = $input.params().querystring )
    "query": $loop,

    #set( $map = $input.params().path )
    "path": $loop,

    #set( $map = $context.identity )
    "identity": $loop,

    #set( $map = $stageVariables )
    "stageVariables": $loop,

    "requestPath": "$context.resourcePath"
}
"""


class TestTemplates:
    @pytest.mark.parametrize("template", [RequestTemplates(), ResponseTemplates()])
    def test_render_custom_template(self, template):
        api_context = ApiInvocationContext(
            method="POST",
            path="/foo/bar?baz=test",
            data=b'{"spam": "eggs"}',
            headers={"content-type": APPLICATION_JSON},
            stage="local",
        )
        api_context.integration = {
            "requestTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE},
            "integrationResponses": {
                "200": {"responseTemplates": {APPLICATION_JSON: RESPONSE_TEMPLATE}}
            },
        }
        api_context.resource_path = "/{proxy+}"
        api_context.path_params = {"id": "bar"}
        api_context.response = requests_response({"spam": "eggs"})
        api_context.context = {
            "httpMethod": api_context.method,
            "stage": api_context.stage,
            "authorizer": {"principalId": "12233"},
            "identity": {"accountId": "00000", "apiKey": "11111"},
            "resourcePath": api_context.resource_path,
        }
        api_context.stage_variables = {"stageVariable1": "value1", "stageVariable2": "value2"}

        rendered_request = template.render(api_context=api_context)
        result_as_json = json.loads(rendered_request)

        assert result_as_json.get("body") == {"spam": "eggs"}
        assert result_as_json.get("method") == "POST"
        assert result_as_json.get("principalId") == "12233"
        assert result_as_json.get("stage") == "local"
        assert result_as_json.get("enhancedAuthContext") == {"principalId": "12233"}
        assert result_as_json.get("identity") == {"accountId": "00000", "apiKey": "11111"}
        assert result_as_json.get("headers") == {"content-type": APPLICATION_JSON}
        assert result_as_json.get("query") == {"baz": "test"}
        assert result_as_json.get("path") == {"id": "bar"}
        assert result_as_json.get("stageVariables") == {
            "stageVariable1": "value1",
            "stageVariable2": "value2",
        }


def test_openapi_resolver_given_unresolvable_references():
    document = {
        "schema": {"$ref": "#/definitions/NotFound"},
        "definitions": {"Found": {"type": "string"}},
    }
    resolver = Resolver(document, allow_recursive=True)
    result = resolver.resolve_references()
    assert result == {"schema": None, "definitions": {"Found": {"type": "string"}}}


def test_openapi_resolver_given_invalid_references():
    document = {"schema": {"$ref": ""}, "definitions": {"Found": {"type": "string"}}}
    resolver = Resolver(document, allow_recursive=True)
    result = resolver.resolve_references()
    assert result == {"schema": None, "definitions": {"Found": {"type": "string"}}}


def test_openapi_resolver_given_list_references():
    document = {
        "schema": {"$ref": "#/definitions/Found"},
        "definitions": {"Found": {"value": ["v1", "v2"]}},
    }
    resolver = Resolver(document, allow_recursive=True)
    result = resolver.resolve_references()
    assert result == {
        "schema": {"value": ["v1", "v2"]},
        "definitions": {"Found": {"value": ["v1", "v2"]}},
    }


def test_create_invocation_headers():
    invocation_context = ApiInvocationContext(
        method="GET", path="/", data="", headers={"X-Header": "foobar"}
    )
    invocation_context.integration = {
        "requestParameters": {"integration.request.header.X-Custom": "'Event'"}
    }
    headers = create_invocation_headers(invocation_context)
    assert headers == {"X-Header": "foobar", "X-Custom": "'Event'"}

    invocation_context.integration = {
        "requestParameters": {"integration.request.path.foobar": "'CustomValue'"}
    }
    headers = create_invocation_headers(invocation_context)
    assert headers == {"X-Header": "foobar", "X-Custom": "'Event'"}


class TestApigatewayEvents:
    def test_construct_invocation_event(self):
        tt = [
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": None,
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": None,
                    "multiValueQueryStringParameters": None,
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": {},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": None,
                    "multiValueQueryStringParameters": None,
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud",
                "headers": {},
                "data": None,
                "query_string_params": {"foo": "bar"},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": {"foo": "bar"},
                    "multiValueQueryStringParameters": {"foo": ("bar",)},
                },
            },
            {
                "method": "GET",
                "path": "http://localhost.localstack.cloud?baz=qux",
                "headers": {},
                "data": None,
                "query_string_params": {"foo": "bar"},
                "is_base64_encoded": False,
                "expected": {
                    "path": "http://localhost.localstack.cloud?baz=qux",
                    "headers": {},
                    "multiValueHeaders": {},
                    "body": None,
                    "isBase64Encoded": False,
                    "httpMethod": "GET",
                    "queryStringParameters": {"foo": "bar"},
                    "multiValueQueryStringParameters": {"foo": ("bar",)},
                },
            },
        ]

        for t in tt:
            result = LambdaProxyIntegration.construct_invocation_event(
                t["method"],
                t["path"],
                t["headers"],
                t["data"],
                t["query_string_params"],
                t["is_base64_encoded"],
            )
            assert result == t["expected"]
