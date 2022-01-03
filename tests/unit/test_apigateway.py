import json
import unittest

from localstack.services.apigateway import apigateway_listener
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
