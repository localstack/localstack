import unittest
from localstack.utils.aws import templating
from localstack.services.apigateway import apigateway_listener


class ApiGatewayPathsTest(unittest.TestCase):

    def test_extract_query_params(self):
        path, query_params = apigateway_listener.extract_query_string_params(
            '/foo/bar?foo=foo&bar=bar&bar=baz'
        )
        self.assertEqual('/foo/bar', path)
        self.assertEqual({'foo': 'foo', 'bar': ['bar', 'baz']}, query_params)

    def test_extract_path_params(self):
        params = apigateway_listener.extract_path_params('/foo/bar', '/foo/{param1}')
        self.assertEqual({'param1': 'bar'}, params)

        params = apigateway_listener.extract_path_params('/foo/bar1/bar2', '/foo/{param1}/{param2}')
        self.assertEqual({'param1': 'bar1', 'param2': 'bar2'}, params)

        params = apigateway_listener.extract_path_params('/foo/bar', '/foo/bar')
        self.assertEqual({}, params)

        params = apigateway_listener.extract_path_params('/foo/bar/baz', '/foo/{proxy+}')
        self.assertEqual({'proxy+': 'bar/baz'}, params)

    def test_path_matches(self):
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/{param1}': {}})
        self.assertEqual('/foo/{param1}', path)

        path, details = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/bar': {}, '/foo/{param1}': {}})
        self.assertEqual('/foo/bar', path)

        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', {'/foo/bar': {}, '/foo/{proxy+}': {}})
        self.assertEqual('/foo/{proxy+}', path)

        result = apigateway_listener.get_resource_for_path('/foo/bar', {'/foo/bar1': {}, '/foo/bar2': {}})
        self.assertEqual(None, result)

        result = apigateway_listener.get_resource_for_path('/foo/bar', {'/{param1}/bar1': {}, '/foo/bar2': {}})
        self.assertEqual(None, result)

        path_args = {'/{param1}/{param2}/foo/{param3}': {}, '/{param}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', path_args)
        self.assertEqual('/{param}/bar', path)

        path_args = {'/{param1}/{param2}': {}, '/{param}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar', path_args)
        self.assertEqual('/{param}/bar', path)

        path_args = {'/{param1}/{param2}': {}, '/{param1}/bar': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/baz', path_args)
        self.assertEqual('/{param1}/{param2}', path)

        path_args = {'/{param1}/{param2}/baz': {}, '/{param1}/bar/{param2}': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual('/{param1}/{param2}/baz', path)

        path_args = {'/{param1}/{param2}/baz': {}, '/{param1}/{param2}/{param2}': {}}
        path, details = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual('/{param1}/{param2}/baz', path)

        path_args = {'/foo123/{param1}/baz': {}}
        result = apigateway_listener.get_resource_for_path('/foo/bar/baz', path_args)
        self.assertEqual(None, result)


class TestVelocityUtil(unittest.TestCase):

    def test_render_template_values(self):
        util = templating.VelocityUtil()

        encoded = util.urlEncode('x=a+b')
        self.assertEqual('x%3Da%2Bb', encoded)

        decoded = util.urlDecode('x=a+b')
        self.assertEqual('x=a b', decoded)

        escaped = util.escapeJavaScript("it's")
        self.assertEqual(r"it\'s", escaped)
