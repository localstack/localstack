import json
from requests.models import Response
from localstack.constants import DEFAULT_REGION
from localstack.config import INBOUND_GATEWAY_URL_PATTERN
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, load_file
from localstack.utils.common import safe_requests as requests
from localstack.services.generic_proxy import GenericProxy, ProxyListener
from localstack.services.awslambda.lambda_api import (LAMBDA_RUNTIME_PYTHON27)
from .test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_LIBS

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
API_PATH_LAMBDA_PROXY_BACKEND = '/lambda/{test_param1}'
# name of Kinesis stream connected to API Gateway
TEST_STREAM_KINESIS_API_GW = 'test-stream-api-gw'
TEST_STAGE_NAME = 'testing'
TEST_LAMBDA_PROXY_BACKEND = 'test_lambda_apigw_backend'


def connect_api_gateway_to_kinesis(gateway_name, kinesis_stream):
    resources = {}
    template = APIGATEWAY_DATA_INBOUND_TEMPLATE % (kinesis_stream)
    resource_path = API_PATH_DATA_INBOUND.replace('/', '')
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
    return aws_stack.create_api_gateway(name=gateway_name, resources=resources,
        stage_name=TEST_STAGE_NAME)


def connect_api_gateway_to_http(gateway_name, target_url, methods=[], path=None):
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
    return aws_stack.create_api_gateway(name=gateway_name, resources=resources,
        stage_name=TEST_STAGE_NAME)


def connect_api_gateway_to_http_with_lambda_proxy(gateway_name, target_uri, methods=[], path=None):
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
    return aws_stack.create_api_gateway(name=gateway_name, resources=resources,
        stage_name=TEST_STAGE_NAME)


def test_api_gateway_kinesis_integration():
    # create target Kinesis stream
    aws_stack.create_kinesis_stream(TEST_STREAM_KINESIS_API_GW)

    # create API Gateway and connect it to the target stream
    result = connect_api_gateway_to_kinesis('test_gateway1', TEST_STREAM_KINESIS_API_GW)

    # generate test data
    test_data = {'records': [
        {'data': '{"foo": "bar1"}'},
        {'data': '{"foo": "bar2"}'},
        {'data': '{"foo": "bar3"}'}
    ]}

    url = INBOUND_GATEWAY_URL_PATTERN.format(api_id=result['id'],
        stage_name=TEST_STAGE_NAME, path=API_PATH_DATA_INBOUND)
    result = requests.post(url, data=json.dumps(test_data))
    result = json.loads(to_str(result.content))
    assert result['FailedRecordCount'] == 0
    assert len(result['Records']) == len(test_data['records'])


def test_api_gateway_http_integration():
    test_port = 12123
    backend_url = 'http://localhost:%s%s' % (test_port, API_PATH_HTTP_BACKEND)

    # create target HTTP backend
    class TestListener(ProxyListener):

        def forward_request(self, **kwargs):
            response = Response()
            response.status_code = 200
            response._content = json.dumps(kwargs['data']) if kwargs['data'] else '{}'
            return response

    proxy = GenericProxy(test_port, update_listener=TestListener())
    proxy.start()

    # create API Gateway and connect it to the HTTP backend
    result = connect_api_gateway_to_http('test_gateway2', backend_url, path=API_PATH_HTTP_BACKEND)

    # make test request to gateway
    url = INBOUND_GATEWAY_URL_PATTERN.format(api_id=result['id'],
        stage_name=TEST_STAGE_NAME, path=API_PATH_HTTP_BACKEND)
    result = requests.get(url)
    assert result.status_code == 200
    assert to_str(result.content) == '{}'
    data = {'data': 123}
    result = requests.post(url, data=json.dumps(data))
    assert result.status_code == 200
    assert json.loads(to_str(result.content)) == data

    # clean up
    proxy.stop()


def test_api_gateway_lambda_proxy_integration():
    # create lambda function
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_PROXY_BACKEND,
        zip_file=zip_file, runtime=LAMBDA_RUNTIME_PYTHON27)

    # create API Gateway and connect it to the Lambda proxy backend
    lambda_uri = aws_stack.lambda_function_arn(TEST_LAMBDA_PROXY_BACKEND)
    target_uri = 'arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations' % (DEFAULT_REGION, lambda_uri)
    result = connect_api_gateway_to_http_with_lambda_proxy('test_gateway2', target_uri,
        path=API_PATH_LAMBDA_PROXY_BACKEND)

    # make test request to gateway and check response
    path = API_PATH_LAMBDA_PROXY_BACKEND.replace('{test_param1}', 'foo1')
    url = INBOUND_GATEWAY_URL_PATTERN.format(api_id=result['id'], stage_name=TEST_STAGE_NAME, path=path)
    data = {'return_status_code': 203, 'return_headers': {'foo': 'bar123'}}
    result = requests.post(url, data=json.dumps(data))
    assert result.status_code == 203
    assert result.headers.get('foo') == 'bar123'
    parsed_body = json.loads(to_str(result.content))
    assert parsed_body.get('return_status_code') == 203
    assert parsed_body.get('return_headers') == {'foo': 'bar123'}
    assert parsed_body.get('pathParameters') == {'test_param1': 'foo1'}
