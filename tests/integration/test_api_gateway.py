# -*- coding: utf-8 -*-

import base64
import re
import json
import unittest
from jsonpatch import apply_patch
from requests.models import Response
from xml.dom.minidom import parseString
from requests.structures import CaseInsensitiveDict
from localstack.config import INBOUND_GATEWAY_URL_PATTERN, DEFAULT_REGION
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, load_file, json_safe, clone
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.services.awslambda.lambda_api import (
    LAMBDA_RUNTIME_PYTHON27, add_event_source)
from localstack.services.apigateway.helpers import (
    get_rest_api_paths, get_resource_for_path, connect_api_gateway_to_sqs)
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
    TEST_SQS_QUEUE = 'test-sqs-queue-api-gw'
    TEST_STAGE_NAME = 'testing'
    TEST_LAMBDA_PROXY_BACKEND = 'test_lambda_apigw_backend'
    TEST_LAMBDA_PROXY_BACKEND_WITH_PATH_PARAM = 'test_lambda_apigw_backend_path_param'
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD = 'test_ARMlambda_apigw_backend_any_method'
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = 'test_ARMlambda_apigw_backend_any_method_path_param'
    TEST_LAMBDA_SQS_HANDLER_NAME = 'lambda_sqs_handler'
    TEST_LAMBDA_AUTHORIZER_HANDLER_NAME = 'lambda_authorizer_handler'
    TEST_API_GATEWAY_ID = 'fugvjdxtri'

    TEST_API_GATEWAY_AUTHORIZER = {
        'name': 'test',
        'type': 'TOKEN',
        'providerARNs': [
            'arn:aws:cognito-idp:us-east-1:123412341234:userpool/us-east-1_123412341'
        ],
        'authType': 'custom',
        'authorizerUri': 'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/' +
                         'arn:aws:lambda:us-east-1:123456789012:function:myApiAuthorizer/invocations',
        'authorizerCredentials': 'arn:aws:iam::123456789012:role/apigAwsProxyRole',
        'identitySource': 'method.request.header.Authorization',
        'identityValidationExpression': '.*',
        'authorizerResultTtlInSeconds': 300
    }
    TEST_API_GATEWAY_AUTHORIZER_OPS = [
        {
            'op': 'replace',
            'path': '/name',
            'value': 'test1'
        }
    ]

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

        # list Kinesis streams via API Gateway
        result = requests.get(url)
        result = json.loads(to_str(result.content))
        self.assertIn('StreamNames', result)

        # post test data to Kinesis via API Gateway
        result = requests.post(url, data=json.dumps(test_data))
        result = json.loads(to_str(result.content))
        self.assertEqual(result['FailedRecordCount'], 0)
        self.assertEqual(len(result['Records']), len(test_data['records']))

        # clean up
        kinesis = aws_stack.connect_to_service('kinesis')
        kinesis.delete_stream(StreamName=self.TEST_STREAM_KINESIS_API_GW)

    def test_api_gateway_sqs_integration_with_event_source(self):
        # create target SQS stream
        aws_stack.create_sqs_queue(self.TEST_SQS_QUEUE)

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs(
            'test_gateway4',
            stage_name=self.TEST_STAGE_NAME,
            queue_arn=self.TEST_SQS_QUEUE, path=self.API_PATH_DATA_INBOUND)

        # create event source for sqs lambda processor
        self.create_lambda_function(self.TEST_LAMBDA_SQS_HANDLER_NAME)
        add_event_source(
            self.TEST_LAMBDA_SQS_HANDLER_NAME,
            aws_stack.sqs_queue_arn(self.TEST_SQS_QUEUE),
            True)

        # generate test data
        test_data = {'spam': 'eggs & beans'}

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND
        )
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(result.status_code, 200)

        parsed_content = parseString(result.content)
        root = parsed_content.documentElement.childNodes[1]

        attr_md5 = root.childNodes[1].lastChild.nodeValue
        body_md5 = root.childNodes[3].lastChild.nodeValue

        self.assertEqual(attr_md5, '4141913720225b35a836dd9e19fc1e55')
        self.assertEqual(body_md5, 'b639f52308afd65866c86f274c59033f')

    def test_api_gateway_sqs_integration(self):
        # create target SQS stream
        aws_stack.create_sqs_queue(self.TEST_SQS_QUEUE)

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs('test_gateway4', stage_name=self.TEST_STAGE_NAME,
            queue_arn=self.TEST_SQS_QUEUE, path=self.API_PATH_DATA_INBOUND)

        # generate test data
        test_data = {'spam': 'eggs'}

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'],
            stage_name=self.TEST_STAGE_NAME,
            path=self.API_PATH_DATA_INBOUND
        )
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(result.status_code, 200)

        messages = aws_stack.sqs_receive_message(self.TEST_SQS_QUEUE)['Messages']
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(base64.b64decode(messages[0]['Body'])), test_data)

    def test_api_gateway_http_integration(self):
        test_port = 12123
        backend_url = 'http://localhost:%s%s' % (test_port, self.API_PATH_HTTP_BACKEND)

        # create target HTTP backend
        class TestListener(ProxyListener):

            def forward_request(self, **kwargs):
                response = Response()
                response.status_code = 200
                result = {
                    'data': kwargs.get('data') or '{}',
                    'headers': dict(kwargs.get('headers'))
                }
                response._content = json.dumps(json_safe(result))
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

        # make test GET request to gateway
        result = requests.get(url)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(to_str(result.content))['data'], '{}')

        # make test POST request to gateway
        data = json.dumps({'data': 123})
        result = requests.post(url, data=data)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(json.loads(to_str(result.content))['data'], data)

        # make test POST request with non-JSON content type
        data = 'test=123'
        ctype = 'application/x-www-form-urlencoded'
        result = requests.post(url, data=data, headers={'content-type': ctype})
        self.assertEqual(result.status_code, 200)
        content = json.loads(to_str(result.content))
        headers = CaseInsensitiveDict(content['headers'])
        self.assertEqual(content['data'], data)
        self.assertEqual(headers['content-type'], ctype)

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

        self.create_lambda_function(fn_name)
        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        invocation_uri = 'arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations'
        target_uri = invocation_uri % (DEFAULT_REGION, lambda_uri)

        result = self.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway2', target_uri, path=path)

        api_id = result['id']
        path_map = get_rest_api_paths(api_id)
        _, resource = get_resource_for_path('/lambda/foo1', path_map)

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        path = path + '?foo=foo&bar=bar&bar=baz'

        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=api_id, stage_name=self.TEST_STAGE_NAME, path=path)

        data = {'return_status_code': 203, 'return_headers': {'foo': 'bar123'}}
        result = requests.post(url, data=json.dumps(data),
            headers={'User-Agent': 'python-requests/testing'})

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

        # send message with non-ASCII chars
        body_msg = '🙀 - 参よ'
        result = requests.post(url, data=json.dumps({'return_raw_body': body_msg}))
        self.assertEqual(to_str(result.content), body_msg)

    def test_api_gateway_lambda_proxy_integration_any_method(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD)

    def test_api_gateway_lambda_proxy_integration_any_method_with_path_param(self):
        self._test_api_gateway_lambda_proxy_integration_any_method(
            self.TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM,
            self.API_PATH_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM)

    def test_api_gateway_authorizer_crud(self):

        apig = aws_stack.connect_to_service('apigateway')

        authorizer = apig.create_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            **self.TEST_API_GATEWAY_AUTHORIZER)

        authorizer_id = authorizer.get('id')

        create_result = apig.get_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            authorizerId=authorizer_id)

        # ignore boto3 stuff
        del create_result['ResponseMetadata']

        create_expected = clone(self.TEST_API_GATEWAY_AUTHORIZER)
        create_expected['id'] = authorizer_id

        self.assertDictEqual(create_expected, create_result)

        apig.update_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            authorizerId=authorizer_id,
            patchOperations=self.TEST_API_GATEWAY_AUTHORIZER_OPS)

        update_result = apig.get_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            authorizerId=authorizer_id)

        # ignore boto3 stuff
        del update_result['ResponseMetadata']

        update_expected = apply_patch(create_expected, self.TEST_API_GATEWAY_AUTHORIZER_OPS)

        self.assertDictEqual(update_expected, update_result)

        apig.delete_authorizer(
            restApiId=self.TEST_API_GATEWAY_ID,
            authorizerId=authorizer_id)

        self.assertRaises(
            Exception,
            apig.get_authorizer,
            self.TEST_API_GATEWAY_ID,
            authorizer_id)

    def _test_api_gateway_lambda_proxy_integration_any_method(self, fn_name, path):
        self.create_lambda_function(fn_name)

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        result = self.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway3', target_uri, methods=['ANY'], path=path)

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        url = INBOUND_GATEWAY_URL_PATTERN.format(
            api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=path)
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
        }, {
            'httpMethod': 'GET',
            'authorizationType': 'NONE',
            'integrations': [{
                'type': 'AWS',
                'uri': 'arn:aws:apigateway:%s:kinesis:action/ListStreams' % DEFAULT_REGION,
                'requestTemplates': {
                    'application/json': '{}'
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

    def create_lambda_function(self, fn_name):
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
