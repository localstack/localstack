import unittest
from localstack.services.apigateway import apigateway_listener


class ApiGatewayPathsTest (unittest.TestCase):

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
