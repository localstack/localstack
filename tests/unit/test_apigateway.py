import unittest
from localstack.utils.aws import templating
from localstack.services.apigateway import apigateway_listener


class ApiGatewayPathsTest(unittest.TestCase):

    def test_extract_query_params(self):
        path, query_params = apigateway_listener.extract_query_string_params(
            '/foo/bar?foo=foo&bar=bar&bar=baz'
        )
        self.assertEqual(path, '/foo/bar')
        self.assertEqual(query_params, {'foo': 'foo', 'bar': ['bar', 'baz']})

    def test_extract_path_params(self):
        params = apigateway_listener.extract_path_params('/foo/bar', '/foo/{param1}')
        self.assertEqual(params, {'param1': 'bar'})

        params = apigateway_listener.extract_path_params('/foo/bar1/bar2', '/foo/{param1}/{param2}')
        self.assertEqual(params, {'param1': 'bar1', 'param2': 'bar2'})

        params = apigateway_listener.extract_path_params('/foo/bar', '/foo/bar')
        self.assertEqual(params, {})

        params = apigateway_listener.extract_path_params('/foo/bar/baz', '/foo/{proxy+}')
        self.assertEqual(params, {'proxy+': 'bar/baz'})

    def test_path_matches(self):
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/{param1}': {}})
        self.assertEqual(path, '/foo/{param1}')

        path, details = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/bar': {}, '/foo/{param1}': {}})
        self.assertEqual(path, '/foo/bar')

        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', {'/foo/bar': {}, '/foo/{proxy+}': {}})
        self.assertEqual(path, '/foo/{proxy+}')

        result = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/bar1': {}, '/foo/bar2': {}})
        self.assertEqual(result, None)

        result = apigateway_listener.get_resource_for_path('/foo/bar', {'/{param1}/bar1': {}, '/foo/bar2': {}})
        self.assertEqual(result, None)

        path_args = {'/{param1}/{param2}/foo/{param3}': {}, '/{param}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', path_args)
        self.assertEqual(path, '/{param}/bar')

        path_args = {'/{param1}/{param2}': {}, '/{param}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', path_args)
        self.assertEqual(path, '/{param}/bar')

        path_args = {'/{param1}/{param2}': {}, '/{param1}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/baz', path_args)
        self.assertEqual(path, '/{param1}/{param2}')

        path_args = {'/{param1}/{param2}/baz': {}, '/{param1}/bar/{param2}': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual(path, '/{param1}/{param2}/baz')

        path_args = {'/{param1}/{param2}/baz': {}, '/{param1}/{param2}/{param2}': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual(path, '/{param1}/{param2}/baz')

        path_args = {'/foo123/{param1}/baz': {}}
        result = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual(result, None)


class TestVelocityUtil(unittest.TestCase):

    def test_render_template_values(self):
        util = templating.VelocityUtil()

        encoded = util.urlEncode('x=a+b')
        self.assertEqual(encoded, 'x%3Da%2Bb')

        decoded = util.urlDecode('x=a+b')
        self.assertEqual(decoded, 'x=a b')

        escaped = util.escapeJavaScript("it's")
        self.assertEqual(escaped, r"it\'s")
