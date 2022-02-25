import json
import unittest
from unittest.mock import Mock

import boto3

from localstack.constants import APPLICATION_JSON
from localstack.services.apigateway import apigateway_listener
from localstack.services.apigateway.apigateway_listener import (
    ApiInvocationContext,
    RequestValidator,
    apply_template,
)
from localstack.services.apigateway.helpers import apply_json_patch_safe
from localstack.utils.aws import templating
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
        apigateway_client = Mock(boto3.client(service_name="apigateway"))
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
        apigateway_client = Mock(boto3.client(service_name="apigateway"))
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
        apigateway_client = Mock(boto3.client(service_name="apigateway"))
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


def test_render_template_values():
    util = templating.VelocityUtil()

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
        int_type = {
            "type": "HTTP",
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }
        resp_type = "request"
        inv_payload = '{"action":"$default","message":"foobar"}'
        rendered = apply_template(int_type, resp_type, inv_payload)

        self.assertEqual('"foobar"', rendered)

    def test_apply_template_no_json_payload(self):
        int_type = {
            "type": "HTTP",
            "requestTemplates": {
                APPLICATION_JSON: "$util.escapeJavaScript($input.json('$.message'))"
            },
        }
        resp_type = "request"
        inv_payload = "#foobar123"
        rendered = apply_template(int_type, resp_type, inv_payload)

        self.assertEqual("[]", rendered)
