import re
import json
import unittest
from requests.models import Response
from localstack.constants import DEFAULT_REGION, TEST_AWS_ACCOUNT_ID
from localstack.config import INBOUND_GATEWAY_URL_PATTERN
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, load_file
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.services.awslambda.lambda_api import (LAMBDA_RUNTIME_PYTHON27)
from localstack.services.apigateway.helpers import get_rest_api_paths, get_resource_for_path
from .test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_LIBS


class TestAPIGatewayIntegrations(unittest.TestCase):
    # template used to transform incoming requests at the API Gateway (stream name to be filled in later)
    APIGATEWAY_DATA_INBOUND_TEMPLATE = """{
        "StreamName": "%s",
        "Records": [
            #set( $numRecords = $input.path('$.records').size() )
            #if($numRecords > 0)
            #set( $maxIndex = $numRecords - 1 )
            #foreach( $idx in [0..$maxIndex] )
            #set( $elem = $input.path("$.records[${idx}]") )
            #set( $elemJsonB64 = $util.base64Encode($elem.data) )
            {
                "Data": "$elemJsonB64",
                "PartitionKey": #if( $elem.partitionKey != '')"$elem.partitionKey"
                                #else"$elemJsonB64.length()"#end
            }#if($foreach.hasNext),#end
            #end
            #end
        ]
    }"""

    # endpoint paths
    API_PATH_DATA_INBOUND = '/data'
    API_PATH_HTTP_BACKEND = '/hello_world'
    API_PATH_LAMBDA_PROXY_BACKEND = '/lambda/foo1'
    API_PATH_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM = '/lambda/{test_param1}'

    API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD = '/lambda-any-method/foo1'
    API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = '/lambda-any-method/{test_param1}'

    # name of Kinesis stream connected to API Gateway
    TEST_STREAM_KINESIS_API_GW = 'test-stream-api-gw'
    TEST_STAGE_NAME = 'testing'
    TEST_LAMBDA_PROXY_BACKEND = 'test_lambda_apigw_backend'
    TEST_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM = 'test_lambda_apigw_backend_path_param'
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD = 'test_ARMlambda_apigw_backend_any_method'
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = 'test_ARMlambda_apigw_backend_any_method_path_param'

    def test_api_gateway_kinesis_integration(self):
        # create target Kinesis stream
        aws_stack.create_kinesis_stream(self.TEST_STREAM_KINESIS_API_GW)

        # create API Gateway and connect it to the target stream
        result = self.connect_api_gateway_to_kinesis('test_gateway1', self.TEST_STREAM_KINESIS_API_GW)

        # generate test data
        test_data = {'records': [
            {'data': '{"foo": "bar1"}'},
            {'data': '{"foo": "bar2"}'},
            {'data': '{"foo": "bar3"}'}
        ]}

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND
        )
        result = requests.post(url, data=json.dumps(test_data))
        result = json.loads(to_str(result.content))

        self.assertEqual(result['FailedRecordCount'], 0)
        self.assertEqual(len(result['Records']), len(test_data['records']))

    def test_api_gateway_http_integration(self):
        test_port = 12123
        backend_url = 'http://localhost:%s%s' % (test_port, self.API_PATH_HTTP_BACKEND)

        # create target HTTP backend
        class TestListener(ProxyListener):

            def forward_request(self, **kwargs):
                response = Response()
                response.status_code = 200
                response._content = kwargs.get('data') or '{}'
                return response

        proxy = GenericProxy(test_port, update_listener=TestListener())
        proxy.start()

        # create API Gateway and connect it to the HTTP backend
        result = self.connect_api_gateway_to_http(
            'test_gateway2',
            backend_url,
            path=self.API_PATH_HTTP_BACKEND
        )

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_HTTP_BACKEND
        )

        # make sure CORS headers are present
        origin = 'localhost'
        result = requests.options(url, headers={'origin': origin})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(re.match(result.headers['Access-Control-Allow-Origin'].replace('*', '.*'), origin))
        self.assertIn('POST', result.headers['Access-Control-Allow-Methods'])

        # make test request to gateway
        result = requests.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(to_str(result.content), '{}')

        data = {'data': 123}
        result = requests.post(url, data=json.dumps(data))
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(to_str(result.content)), data)

        # clean up
        proxy.stop()

    def test_api_gateway_lambda_proxy_integration(self):
        self._test_api_gateway_lambda_proxy_integration(
            self.TEST_LAMBDA_PROXY_BACKEND,
            self.API_PATH_LAMBDA_PROXY_BACKEND)

    def test_api_gateway_lambda_proxy_integration_with_path_param(self):
        self._test_api_gateway_lambda_proxy_integration(
            self.TEST_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM,
            self.API_PATH_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM)

    def _test_api_gateway_lambda_proxy_integration(self, fn_name, path):
        # create lambda function
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=fn_name,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        invocation_uri = 'arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations'
        target_uri = invocation_uri % (DEFAULT_REGION, lambda_uri)

        result = self.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway2',
            target_uri,
            path=path
        )

        api_id = result['id']
        path_map = get_rest_api_paths(api_id)
        _, resource = get_resource_for_path('/lambda/foo1', path_map)

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        path = path + '?foo=foo&bar=bar&bar=baz'

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=api_id,
            stage_name=self.TEST_STAGE_NAME,
            path=path
        )

        data = {'return_status_code': 203, 'return_headers': {'foo': 'bar123'}}
        result = requests.post(
            url,
            data=json.dumps(data),
            headers={'User-Agent': 'python-requests/testing'}
        )

        self.assertEqual(result.status_code, 203)
        self.assertEqual(result.headers.get('foo'), 'bar123')

        parsed_body = json.loads(to_str(result.content))
        self.assertEqual(parsed_body.get('return_status_code'), 203)
        self.assertDictEqual(parsed_body.get('return_headers'), {'foo': 'bar123'})
        self.assertDictEqual(parsed_body.get('queryStringParameters'), {'foo': 'foo', 'bar': ['bar', 'baz']})

        request_context = parsed_body.get('requestContext')
        source_ip = request_context['identity'].pop('sourceIp')

        self.assertTrue(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', source_ip))

        self.assertEqual(request_context['path'], '/lambda/foo1')
        self.assertEqual(request_context['accountId'], TEST_AWS_ACCOUNT_ID)
        self.assertEqual(request_context['resourceId'], resource.get('id'))
        self.assertEqual(request_context['stage'], self.TEST_STAGE_NAME)
        self.assertEqual(request_context['identity']['userAgent'], 'python-requests/testing')

        result = requests.delete(url, data=json.dumps(data))
        self.assertEqual(result.status_code, 404)

    def test_api_gateway_lambda_proxy_integration_any_method(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD)

    def test_api_gateway_lambda_proxy_integration_any_method_with_path_param(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM)

    def _test_api_gateway_lambda_proxy_integration_any_method(self, fn_name, path):
        # create lambda function
        zip_file = testutil.create_lambda_archive(
            load_file(TEST_LAMBDA_PYTHON),
            get_content=True,
            libs=TEST_LAMBDA_LIBS,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )
        testutil.create_lambda_function(
            func_name=fn_name,
            zip_file=zip_file,
            runtime=LAMBDA_RUNTIME_PYTHON27
        )

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        result = self.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway3',
            target_uri,
            methods=['ANY'],
            path=path
        )

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'],
            stage_name=self.TEST_STAGE_NAME,
            path=path
        )
        data = {}

        for method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            body = json.dumps(data) if method in ('POST', 'PUT', 'PATCH') else None
            result = getattr(requests, method.lower())(url, data=body)
            self.assertEqual(result.status_code, 200)
            parsed_body = json.loads(to_str(result.content))
            self.assertEqual(parsed_body.get('httpMethod'), method)

    # =====================================================================
    # Helper methods
    # =====================================================================
    def connect_api_gateway_to_kinesis(self, gateway_name, kinesis_stream):
        resources = {}
        template = self.APIGATEWAY_DATA_INBOUND_TEMPLATE % (kinesis_stream)
        resource_path = self.API_PATH_DATA_INBOUND.replace('/', '')
        resources[resource_path] = [{
            'httpMethod': 'POST',
            'authorizationType': 'NONE',
            'integrations': [{
                'type': 'AWS',
                'uri': 'arn:aws:apigateway:%s:kinesis:action/PutRecords' % DEFAULT_REGION,
                'requestTemplates': {
                    'application/json': template
                }
            }]
        }]
        return aws_stack.create_api_gateway(
            name=gateway_name,
            resources=resources,
            stage_name=self.TEST_STAGE_NAME
        )

    def connect_api_gateway_to_http(self, gateway_name, target_url, methods=[], path=None):
        if not methods:
            methods = ['GET', 'POST']
        if not path:
            path = '/'
        resources = {}
        resource_path = path.replace('/', '')
        resources[resource_path] = []
        for method in methods:
            resources[resource_path].append({
                'httpMethod': method,
                'integrations': [{
                    'type': 'HTTP',
                    'uri': target_url
                }]
            })
        return aws_stack.create_api_gateway(
            name=gateway_name,
            resources=resources,
            stage_name=self.TEST_STAGE_NAME
        )

    def connect_api_gateway_to_http_with_lambda_proxy(self, gateway_name, target_uri, methods=[], path=None):
        if not methods:
            methods = ['GET', 'POST']
        if not path:
            path = '/'
        resources = {}
        resource_path = path.lstrip('/')
        resources[resource_path] = []
        for method in methods:
            resources[resource_path].append({
                'httpMethod': method,
                'integrations': [{
                    'type': 'AWS_PROXY',
                    'uri': target_uri
                }]
            })
        return aws_stack.create_api_gateway(
            name=gateway_name,
            resources=resources,
            stage_name=self.TEST_STAGE_NAME
        )
