# -*- coding: utf-8 -*-
import os
import re
import json
import base64
import unittest
import xmltodict
from botocore.exceptions import ClientError
from jsonpatch import apply_patch
from requests.models import Response
from requests.structures import CaseInsensitiveDict
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import (
    to_str, json_safe, clone, short_uid, get_free_tcp_port, load_file, safe_requests as requests)
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.services.awslambda.lambda_api import add_event_source
from localstack.services.apigateway.helpers import (
    get_rest_api_paths, get_resource_for_path, connect_api_gateway_to_sqs, gateway_request_url)
from .test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_LIBS


THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_SWAGGER_FILE = os.path.join(THIS_FOLDER, 'files', 'swagger.json')


class TestAPIGateway(unittest.TestCase):
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
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD = 'test_lambda_apigw_backend_any_method'
    TEST_LAMBDA_PROXY_BACKEND_ANY_METHOD_WITH_PATH_PARAM = 'test_lambda_apigw_backend_any_method_path_param'
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
        stream = aws_stack.create_kinesis_stream(self.TEST_STREAM_KINESIS_API_GW)
        stream.wait_for()

        # create API Gateway and connect it to the target stream
        result = self.connect_api_gateway_to_kinesis('test_gateway1', self.TEST_STREAM_KINESIS_API_GW)

        # generate test data
        test_data = {'records': [
            {'data': '{"foo": "bar1"}'},
            {'data': '{"foo": "bar2"}'},
            {'data': '{"foo": "bar3"}'}
        ]}

        url = gateway_request_url(
            api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=self.API_PATH_DATA_INBOUND)

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
        queue_name = 'queue-%s' % short_uid()
        queue_url = aws_stack.create_sqs_queue(queue_name)['QueueUrl']

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs(
            'test_gateway4', stage_name=self.TEST_STAGE_NAME,
            queue_arn=queue_name, path=self.API_PATH_DATA_INBOUND)

        # create event source for sqs lambda processor
        self.create_lambda_function(self.TEST_LAMBDA_SQS_HANDLER_NAME)
        add_event_source(
            self.TEST_LAMBDA_SQS_HANDLER_NAME,
            aws_stack.sqs_queue_arn(queue_name),
            True
        )

        # generate test data
        test_data = {'spam': 'eggs & beans'}

        url = gateway_request_url(
            api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=self.API_PATH_DATA_INBOUND)
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(result.status_code, 200)

        parsed_json = xmltodict.parse(result.content)
        result = parsed_json['SendMessageResponse']['SendMessageResult']

        body_md5 = result['MD5OfMessageBody']

        self.assertEqual(body_md5, 'b639f52308afd65866c86f274c59033f')

        # clean up
        sqs_client = aws_stack.connect_to_service('sqs')
        sqs_client.delete_queue(QueueUrl=queue_url)

        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.delete_function(FunctionName=self.TEST_LAMBDA_SQS_HANDLER_NAME)

    def test_api_gateway_sqs_integration(self):
        # create target SQS stream
        queue_name = 'queue-%s' % short_uid()
        aws_stack.create_sqs_queue(queue_name)

        # create API Gateway and connect it to the target queue
        result = connect_api_gateway_to_sqs('test_gateway4', stage_name=self.TEST_STAGE_NAME,
            queue_arn=queue_name, path=self.API_PATH_DATA_INBOUND)

        # generate test data
        test_data = {'spam': 'eggs'}

        url = gateway_request_url(
            api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=self.API_PATH_DATA_INBOUND)
        result = requests.post(url, data=json.dumps(test_data))
        self.assertEqual(result.status_code, 200)

        messages = aws_stack.sqs_receive_message(queue_name)['Messages']
        self.assertEqual(len(messages), 1)
        self.assertEqual(json.loads(base64.b64decode(messages[0]['Body'])), test_data)

    def test_api_gateway_http_integrations(self):
        self.run_api_gateway_http_integration('custom')
        self.run_api_gateway_http_integration('proxy')

    def run_api_gateway_http_integration(self, int_type):
        test_port = get_free_tcp_port()
        backend_url = 'http://localhost:%s%s' % (test_port, self.API_PATH_HTTP_BACKEND)

        # start test HTTP backend
        proxy = self.start_http_backend(test_port)

        # create API Gateway and connect it to the HTTP_PROXY/HTTP backend
        result = self.connect_api_gateway_to_http(
            int_type,
            'test_gateway2',
            backend_url,
            path=self.API_PATH_HTTP_BACKEND
        )

        url = gateway_request_url(
            api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=self.API_PATH_HTTP_BACKEND)

        # make sure CORS headers are present
        origin = 'localhost'
        result = requests.options(url, headers={'origin': origin})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(re.match(result.headers['Access-Control-Allow-Origin'].replace('*', '.*'), origin))
        self.assertIn('POST', result.headers['Access-Control-Allow-Methods'])

        custom_result = json.dumps({'foo': 'bar'})

        # make test GET request to gateway
        result = requests.get(url)
        self.assertEqual(result.status_code, 200)
        expected = custom_result if int_type == 'custom' else '{}'
        self.assertEqual(json.loads(to_str(result.content))['data'], expected)

        # make test POST request to gateway
        data = json.dumps({'data': 123})
        result = requests.post(url, data=data)
        self.assertEqual(result.status_code, 200)
        expected = custom_result if int_type == 'custom' else data
        self.assertEqual(json.loads(to_str(result.content))['data'], expected)

        # make test POST request with non-JSON content type
        data = 'test=123'
        ctype = 'application/x-www-form-urlencoded'
        result = requests.post(url, data=data, headers={'content-type': ctype})
        self.assertEqual(result.status_code, 200)
        content = json.loads(to_str(result.content))
        headers = CaseInsensitiveDict(content['headers'])
        expected = custom_result if int_type == 'custom' else data
        self.assertEqual(content['data'], expected)
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
        target_uri = invocation_uri % (aws_stack.get_region(), lambda_uri)

        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway2', target_uri, path=path, stage_name=self.TEST_STAGE_NAME)

        api_id = result['id']
        path_map = get_rest_api_paths(api_id)
        _, resource = get_resource_for_path('/lambda/foo1', path_map)

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        path = path + '?foo=foo&bar=bar&bar=baz'

        url = gateway_request_url(api_id=api_id, stage_name=self.TEST_STAGE_NAME, path=path)

        data = {'return_status_code': 203, 'return_headers': {'foo': 'bar123'}}
        result = requests.post(url, data=json.dumps(data),
            headers={'User-Agent': 'python-requests/testing'})

        self.assertEqual(result.status_code, 203)
        self.assertEqual(result.headers.get('foo'), 'bar123')
        self.assertIn('set-cookie', result.headers)

        parsed_body = json.loads(to_str(result.content))
        self.assertEqual(parsed_body.get('return_status_code'), 203)
        self.assertDictEqual(parsed_body.get('return_headers'), {'foo': 'bar123'})
        self.assertDictEqual(parsed_body.get('queryStringParameters'), {'foo': 'foo', 'bar': ['bar', 'baz']})

        request_context = parsed_body.get('requestContext')
        source_ip = request_context['identity'].pop('sourceIp')

        self.assertTrue(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', source_ip))

        self.assertEqual(request_context['path'], '/' + self.TEST_STAGE_NAME + '/lambda/foo1')
        self.assertEqual(request_context.get('stageVariables'), None)
        self.assertEqual(request_context['accountId'], TEST_AWS_ACCOUNT_ID)
        self.assertEqual(request_context['resourceId'], resource.get('id'))
        self.assertEqual(request_context['stage'], self.TEST_STAGE_NAME)
        self.assertEqual(request_context['identity']['userAgent'], 'python-requests/testing')
        self.assertEqual(request_context['httpMethod'], 'POST')
        self.assertEqual(request_context['protocol'], 'HTTP/1.1')
        self.assertIn('requestTimeEpoch', request_context)
        self.assertIn('requestTime', request_context)

        result = requests.delete(url, data=json.dumps(data))
        self.assertEqual(result.status_code, 204)

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
            authorizer_id
        )

    def test_apigateway_with_lambda_integration(self):
        apigw_client = aws_stack.connect_to_service('apigateway')

        # create Lambda function
        lambda_name = 'apigw-lambda-%s' % short_uid()
        self.create_lambda_function(lambda_name)
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        # create REST API
        api = apigw_client.create_rest_api(name='test-api', description='')
        api_id = api['id']
        root_res_id = apigw_client.get_resources(restApiId=api_id)['items'][0]['id']
        api_resource = apigw_client.create_resource(restApiId=api_id, parentId=root_res_id, pathPart='test')

        apigw_client.put_method(
            restApiId=api_id,
            resourceId=api_resource['id'],
            httpMethod='GET',
            authorizationType='NONE'
        )

        rs = apigw_client.put_integration(
            restApiId=api_id,
            resourceId=api_resource['id'],
            httpMethod='GET',
            integrationHttpMethod='POST',
            type='AWS',
            uri=target_uri,
            timeoutInMillis=3000,
            contentHandling='CONVERT_TO_BINARY',
            requestTemplates={
                'application/json': '{"param1": "$input.params(\'param1\')"}'
            }
        )
        integration_keys = ['httpMethod', 'type', 'passthroughBehavior', 'cacheKeyParameters', 'uri', 'cacheNamespace',
            'timeoutInMillis', 'contentHandling', 'requestParameters']
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        for key in integration_keys:
            self.assertIn(key, rs)
        self.assertNotIn('responseTemplates', rs)

        apigw_client.create_deployment(restApiId=api_id, stageName=self.TEST_STAGE_NAME)

        rs = apigw_client.get_integration(
            restApiId=api_id,
            resourceId=api_resource['id'],
            httpMethod='GET'
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['type'], 'AWS')
        self.assertEqual(rs['httpMethod'], 'POST')
        self.assertEqual(rs['uri'], target_uri)

        # invoke the gateway endpoint
        url = gateway_request_url(api_id=api_id, stage_name=self.TEST_STAGE_NAME, path='/test')
        response = requests.get('%s?param1=foobar' % url)
        self.assertLess(response.status_code, 400)
        content = json.loads(to_str(response.content))
        self.assertEqual(content.get('httpMethod'), 'GET')
        self.assertEqual(content.get('requestContext', {}).get('resourceId'), api_resource['id'])
        self.assertEqual(content.get('requestContext', {}).get('stage'), self.TEST_STAGE_NAME)
        self.assertEqual(content.get('body'), '{"param1": "foobar"}')

        # delete integration
        rs = apigw_client.delete_integration(
            restApiId=api_id,
            resourceId=api_resource['id'],
            httpMethod='GET',
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        with self.assertRaises(ClientError) as ctx:
            # This call should not be successful as the integration is deleted
            apigw_client.get_integration(
                restApiId=api_id,
                resourceId=api_resource['id'],
                httpMethod='GET'
            )
        self.assertEqual(ctx.exception.response['Error']['Code'], 'BadRequestException')

        # clean up
        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.delete_function(FunctionName=lambda_name)
        apigw_client.delete_rest_api(restApiId=api_id)

    def test_api_gateway_handle_domain_name(self):
        domain_name = '%s.example.com' % short_uid()
        apigw_client = aws_stack.connect_to_service('apigateway')

        rs = apigw_client.create_domain_name(
            domainName=domain_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = apigw_client.get_domain_name(
            domainName=domain_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['domainName'], domain_name)

        # clean up
        apigw_client.delete_domain_name(domainName=domain_name)

    def _test_api_gateway_lambda_proxy_integration_any_method(self, fn_name, path):
        self.create_lambda_function(fn_name)

        # create API Gateway and connect it to the Lambda proxy backend
        lambda_uri = aws_stack.lambda_function_arn(fn_name)
        target_uri = aws_stack.apigateway_invocations_arn(lambda_uri)

        result = testutil.connect_api_gateway_to_http_with_lambda_proxy(
            'test_gateway3', target_uri, methods=['ANY'], path=path, stage_name=self.TEST_STAGE_NAME)

        # make test request to gateway and check response
        path = path.replace('{test_param1}', 'foo1')
        url = gateway_request_url(api_id=result['id'], stage_name=self.TEST_STAGE_NAME, path=path)
        data = {}

        for method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'):
            body = json.dumps(data) if method in ('POST', 'PUT', 'PATCH') else None
            result = getattr(requests, method.lower())(url, data=body)
            if method != 'DELETE':
                self.assertEqual(result.status_code, 200)
                parsed_body = json.loads(to_str(result.content))
                self.assertEqual(parsed_body.get('httpMethod'), method)
            else:
                self.assertEqual(result.status_code, 204)

    def test_apigateway_with_custom_authorization_method(self):
        apigw_client = aws_stack.connect_to_service('apigateway')

        # create Lambda function
        lambda_name = 'apigw-lambda-%s' % short_uid()
        self.create_lambda_function(lambda_name)
        lambda_uri = aws_stack.lambda_function_arn(lambda_name)

        # create REST API
        api = apigw_client.create_rest_api(name='test-api', description='')
        api_id = api['id']
        root_res_id = apigw_client.get_resources(restApiId=api_id)['items'][0]['id']

        # create authorizer at root resource
        authorizer = apigw_client.create_authorizer(
            restApiId=api_id,
            name='lambda_authorizer',
            type='TOKEN',
            authorizerUri='arn:aws:apigateway:us-east-1:lambda:path/ \
                2015-03-31/functions/{}/invocations'.format(lambda_uri),
            identitySource='method.request.header.Auth'
        )

        # create method with custom authorizer
        is_api_key_required = True
        method_response = apigw_client.put_method(
            restApiId=api_id, resourceId=root_res_id, httpMethod='GET', authorizationType='CUSTOM',
            authorizerId=authorizer['id'], apiKeyRequired=is_api_key_required
        )

        self.assertEqual(authorizer['id'], method_response['authorizerId'])

        # clean up
        lambda_client = aws_stack.connect_to_service('lambda')
        lambda_client.delete_function(FunctionName=lambda_name)
        apigw_client.delete_rest_api(restApiId=api_id)

    # =====================================================================
    # Helper methods
    # =====================================================================

    def connect_api_gateway_to_kinesis(self, gateway_name, kinesis_stream):
        resources = {}
        template = self.APIGATEWAY_DATA_INBOUND_TEMPLATE % kinesis_stream
        resource_path = self.API_PATH_DATA_INBOUND.replace('/', '')
        resources[resource_path] = [{
            'httpMethod': 'POST',
            'authorizationType': 'NONE',
            'integrations': [{
                'type': 'AWS',
                'uri': 'arn:aws:apigateway:%s:kinesis:action/PutRecords' % aws_stack.get_region(),
                'requestTemplates': {
                    'application/json': template
                }
            }]
        }, {
            'httpMethod': 'GET',
            'authorizationType': 'NONE',
            'integrations': [{
                'type': 'AWS',
                'uri': 'arn:aws:apigateway:%s:kinesis:action/ListStreams' % aws_stack.get_region(),
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

    def connect_api_gateway_to_http(self, int_type, gateway_name, target_url, methods=[], path=None):
        if not methods:
            methods = ['GET', 'POST']
        if not path:
            path = '/'
        resources = {}
        resource_path = path.replace('/', '')
        resources[resource_path] = []
        req_templates = {
            'application/json': json.dumps({'foo': 'bar'})
        } if int_type == 'custom' else {}
        for method in methods:
            resources[resource_path].append({
                'httpMethod': method,
                'integrations': [{
                    'type': 'HTTP' if int_type == 'custom' else 'HTTP_PROXY',
                    'uri': target_url,
                    'requestTemplates': req_templates,
                    'responseTemplates': {}
                }]
            })
        return aws_stack.create_api_gateway(
            name=gateway_name,
            resources=resources,
            stage_name=self.TEST_STAGE_NAME
        )

    @staticmethod
    def create_lambda_function(fn_name):
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON, libs=TEST_LAMBDA_LIBS, func_name=fn_name)

    def test_create_model(self):
        client = aws_stack.connect_to_service('apigateway')
        response = client.create_rest_api(name='my_api', description='this is my api')
        rest_api_id = response['id']
        dummy_rest_api_id = '_non_existing_'
        model_name = 'testModel'
        description = 'test model'
        content_type = 'application/json'

        # success case with valid params
        response = client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )
        self.assertEqual(response['name'], model_name)
        self.assertEqual(response['description'], description)

        try:
            client.create_model(
                restApiId=dummy_rest_api_id,
                name=model_name,
                description=description,
                contentType=content_type,
            )
            self.fail('This call should not be successful as the rest api is not valid.')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NotFoundException')
            self.assertEqual(e.response['Error']['Message'], 'Invalid Rest API Id specified')

        try:
            client.create_model(
                restApiId=dummy_rest_api_id,
                name='',
                description=description,
                contentType=content_type,
            )
            self.fail('This call should not be successful as the model name is not specified.')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'BadRequestException')
            self.assertEqual(e.response['Error']['Message'], 'No Model Name specified')

    def test_get_api_models(self):
        client = aws_stack.connect_to_service('apigateway')
        response = client.create_rest_api(name='my_api', description='this is my api')
        rest_api_id = response['id']
        model_name = 'testModel'
        description = 'test model'
        content_type = 'application/json'
        # when no models are present
        result = client.get_models(restApiId=rest_api_id)
        self.assertEqual(result['items'], [])
        # add a model
        client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )

        # get models after adding
        result = client.get_models(restApiId=rest_api_id)
        self.assertEqual(result['items'][0]['name'], model_name)
        self.assertEqual(result['items'][0]['description'], description)

    def test_get_model_by_name(self):
        client = aws_stack.connect_to_service('apigateway')
        response = client.create_rest_api(name='my_api', description='this is my api')
        rest_api_id = response['id']
        dummy_rest_api_id = '_non_existing_'
        model_name = 'testModel'
        description = 'test model'
        content_type = 'application/json'
        # add a model
        client.create_model(
            restApiId=rest_api_id,
            name=model_name,
            description=description,
            contentType=content_type,
        )

        # get models after adding
        result = client.get_model(restApiId=rest_api_id, modelName=model_name)
        self.assertEqual(result['name'], model_name)
        self.assertEqual(result['description'], description)

        try:
            client.get_model(restApiId=dummy_rest_api_id, modelName=model_name)
            self.fail('This call should not be successful as the model is not created.')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NotFoundException')
            self.assertEqual(e.response['Error']['Message'], 'Invalid Rest API Id specified')

    def test_get_model_with_invalid_name(self):
        client = aws_stack.connect_to_service('apigateway')
        response = client.create_rest_api(name='my_api', description='this is my api')
        rest_api_id = response['id']

        # test with an invalid model name
        try:
            client.get_model(restApiId=rest_api_id, modelName='fake')
            self.fail('This call should not be successful as the model is not created.')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NotFoundException')

    def test_put_integration_dynamodb_proxy_validation_without_response_template(self):
        api_id = self.create_api_gateway_and_deploy({})
        url = gateway_request_url(api_id=api_id, stage_name='staging', path='/')
        response = requests.put(
            url,
            json.dumps({'id': 'id1', 'data': 'foobar123'}),
        )

        self.assertEqual(response.status_code, 404)

    def test_put_integration_dynamodb_proxy_validation_with_response_template(self):
        response_templates = {'application/json': json.dumps({'TableName': 'MusicCollection',
                                         'Item': {'id': '$.Id', 'data': '$.data'}})}

        api_id = self.create_api_gateway_and_deploy(response_templates)
        url = gateway_request_url(api_id=api_id, stage_name='staging', path='/')

        response = requests.put(
            url,
            json.dumps({'id': 'id1', 'data': 'foobar123'}),
        )

        self.assertEqual(response.status_code, 200)
        dynamo_client = aws_stack.connect_to_resource('dynamodb')
        table = dynamo_client.Table('MusicCollection')
        result = table.get_item(Key={'id': 'id1'})
        self.assertEqual(result['Item']['data'], 'foobar123')

    def test_api_key_required_for_methods(self):
        response_templates = {'application/json': json.dumps({'TableName': 'MusicCollection',
                                                              'Item': {'id': '$.Id', 'data': '$.data'}})}

        api_id = self.create_api_gateway_and_deploy(response_templates, True)
        url = gateway_request_url(api_id=api_id, stage_name='staging', path='/')

        payload = {
            'name': 'TEST-PLAN-2',
            'description': 'Description',
            'quota': {'limit': 10, 'period': 'DAY', 'offset': 0},
            'throttle': {'rateLimit': 2, 'burstLimit': 1},
            'apiStages': [{'apiId': api_id, 'stage': 'staging'}],
            'tags': {'tag_key': 'tag_value'},
        }

        client = aws_stack.connect_to_service('apigateway')
        usage_plan_id = client.create_usage_plan(**payload)['id']

        key_name = 'testApiKey'
        key_type = 'API_KEY'
        api_key = client.create_api_key(name=key_name)

        payload = {'usagePlanId': usage_plan_id, 'keyId': api_key['id'], 'keyType': key_type}
        client.create_usage_plan_key(**payload)

        response = requests.put(
            url,
            json.dumps({'id': 'id1', 'data': 'foobar123'}),
        )
        # when the api key is not passed as part of the header
        self.assertEqual(response.status_code, 403)

        response = requests.put(
            url,
            json.dumps({'id': 'id1', 'data': 'foobar123'}),
            headers={'X-API-Key': api_key['value']}
        )
        # when the api key is passed as part of the header
        self.assertEqual(response.status_code, 200)

    def test_import_rest_api(self):
        rest_api_name = 'restapi-%s' % short_uid()

        client = aws_stack.connect_to_service('apigateway')
        rest_api_id = client.create_rest_api(name=rest_api_name)['id']

        spec_file = load_file(TEST_SWAGGER_FILE)
        rs = client.put_rest_api(
            restApiId=rest_api_id, body=spec_file)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = client.get_resources(restApiId=rest_api_id)
        self.assertEqual(len(rs['items']), 1)

        resource = rs['items'][0]
        self.assertEqual(resource['path'], '/test')
        self.assertIn('GET', resource['resourceMethods'])

        # clean up
        client.delete_rest_api(restApiId=rest_api_id)

    @staticmethod
    def start_http_backend(test_port):
        # test listener for target HTTP backend
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
        return proxy

    @staticmethod
    def create_api_gateway_and_deploy(response_template, is_api_key_required=False):
        apigw_client = aws_stack.connect_to_service('apigateway')
        response = apigw_client.create_rest_api(name='my_api', description='this is my api')
        api_id = response['id']
        resources = apigw_client.get_resources(restApiId=api_id)
        root_resources = [resource for resource in resources['items'] if resource['path'] == '/']
        root_id = root_resources[0]['id']

        apigw_client.put_method(
            restApiId=api_id, resourceId=root_id, httpMethod='PUT', authorizationType='NONE',
            apiKeyRequired=is_api_key_required
        )

        apigw_client.put_method_response(
            restApiId=api_id, resourceId=root_id, httpMethod='PUT', statusCode='200',
        )

        aws_stack.create_dynamodb_table('MusicCollection', partition_key='id')

        # Ensure that it works fine when providing the integrationHttpMethod-argument
        apigw_client.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod='PUT',
            integrationHttpMethod='PUT',
            type='AWS_PROXY',
            uri='arn:aws:apigateway:us-east-1:dynamodb:action/PutItem&Table=MusicCollection',
        )

        apigw_client.put_integration_response(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod='PUT',
            statusCode='200',
            selectionPattern='',
            responseTemplates=response_template)

        apigw_client.create_deployment(restApiId=api_id, stageName='staging')

        return api_id
