import json
import unittest
from unittest.mock import Mock

import boto3
import pytest

from localstack import config
from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway import apigateway_listener
from localstack.services.apigateway.apigateway_listener import (
    ApiInvocationContext,
    RequestValidator,
)
from localstack.services.apigateway.helpers import apply_json_patch_safe
from localstack.services.apigateway.integration import (
    RequestTemplates,
    ResponseTemplates,
    VelocityUtil,
)
from localstack.utils.aws.aws_responses import requests_response
from localstack.utils.common import clone


class ApiGatewayPathsTest(unittest.TestCase):
    def test_extract_query_params(self):
        path, query_params = apigateway_listener.extract_query_string_params(
            "/foo/bar?foo=foo&bar=bar&bar=baz"
        )
        self.assertEqual("/foo/bar", path)
        self.assertEqual({"foo": "foo", "bar": ["bar", "baz"]}, query_params)

    def test_extract_path_params(self):
        params = apigateway_listener.extract_path_params("/foo/bar", "/foo/{param1}")
        self.assertEqual({"param1": "bar"}, params)

        params = apigateway_listener.extract_path_params("/foo/bar1/bar2", "/foo/{param1}/{param2}")
        self.assertEqual({"param1": "bar1", "param2": "bar2"}, params)

        params = apigateway_listener.extract_path_params("/foo/bar", "/foo/bar")
        self.assertEqual({}, params)

        params = apigateway_listener.extract_path_params("/foo/bar/baz", "/foo/{proxy+}")
        self.assertEqual({"proxy": "bar/baz"}, params)

    def test_path_matches(self):
        path, details = apigateway_listener.get_resource_for_path("/foo/bar", {"/foo/{param1}": {}})
        self.assertEqual("/foo/{param1}", path)

        path, details = apigateway_listener.get_resource_for_path(
            "/foo/bar", {"/foo/bar": {}, "/foo/{param1}": {}}
        )
        self.assertEqual("/foo/bar", path)

        path, details = apigateway_listener.get_resource_for_path(
            "/foo/bar/baz", {"/foo/bar": {}, "/foo/{proxy+}": {}}
        )
        self.assertEqual("/foo/{proxy+}", path)

        path, details = apigateway_listener.get_resource_for_path(
            "/foo/bar/baz", {"/{proxy+}": {}, "/foo/{proxy+}": {}}
        )
        self.assertEqual("/foo/{proxy+}", path)

        result = apigateway_listener.get_resource_for_path(
            "/foo/bar", {"/foo/bar1": {}, "/foo/bar2": {}}
        )
        self.assertEqual(None, result)

        result = apigateway_listener.get_resource_for_path(
            "/foo/bar", {"/{param1}/bar1": {}, "/foo/bar2": {}}
        )
        self.assertEqual(None, result)

        path_args = {"/{param1}/{param2}/foo/{param3}": {}, "/{param}/bar": {}}
        path, details = apigateway_listener.get_resource_for_path("/foo/bar", path_args)
        self.assertEqual("/{param}/bar", path)

        path_args = {"/{param1}/{param2}": {}, "/{param}/bar": {}}
        path, details = apigateway_listener.get_resource_for_path("/foo/bar", path_args)
        self.assertEqual("/{param}/bar", path)

        path_args = {"/{param1}/{param2}": {}, "/{param1}/bar": {}}
        path, details = apigateway_listener.get_resource_for_path("/foo/baz", path_args)
        self.assertEqual("/{param1}/{param2}", path)

        path_args = {"/{param1}/{param2}/baz": {}, "/{param1}/bar/{param2}": {}}
        path, details = apigateway_listener.get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual("/{param1}/{param2}/baz", path)

        path_args = {"/{param1}/{param2}/baz": {}, "/{param1}/{param2}/{param2}": {}}
        path, details = apigateway_listener.get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual("/{param1}/{param2}/baz", path)

        path_args = {"/foo123/{param1}/baz": {}}
        result = apigateway_listener.get_resource_for_path("/foo/bar/baz", path_args)
        self.assertEqual(None, result)

        path_args = {"/foo/{param1}/baz": {}, "/foo/{param1}/{param2}": {}}
        path, result = apigateway_listener.get_resource_for_path("/foo/bar/baz", path_args)
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

        uri = apigateway_listener.apply_request_parameters(
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
        return Mock(boto3.client("apigateway", region_name=config.DEFAULT_REGION))


def test_render_template_values():
    util = VelocityUtil()

    encoded = util.urlEncode("x=a+b")
    assert encoded == "x%3Da%2Bb"

    decoded = util.urlDecode("x=a+b")
    assert decoded == "x=a b"

    escape_tests = (
        ("it's", '"it\'s"'),
        ("0010", "10"),
        ("true", "true"),
        ("True", '"True"'),
        ("1.021", "1.021"),
        ("'''", "\"'''\""),
        ('""', '""'),
        ('"""', '"\\"\\"\\""'),
        ('{"foo": 123}', '{"foo": 123}'),
        ('{"foo"": 123}', '"{\\"foo\\"\\": 123}"'),
        (1, "1"),
        (True, "true"),
    )
    for string, expected in escape_tests:
        escaped = util.escapeJavaScript(string)
        assert escaped == expected
        # we should be able to json.loads in all of the cases!
        json.loads(escaped)


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

        self.assertEqual('"foobar"', rendered_request)

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
