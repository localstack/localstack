import json
import requests
from localstack.config import DEFAULT_REGION, INBOUND_GATEWAY_URL_PATTERN
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str


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
# endpoint path
API_PATH_DATA_INBOUND = '/data'
# name of Kinesis stream connected to API Gateway
TEST_STREAM_KINESIS_API_GW = 'test-stream-api-gw'
TEST_STAGE_NAME = 'testing'


def connect_api_gateway_to_kinesis(gateway_name, kinesis_stream):
    resources = {}
    template_data_inbound = APIGATEWAY_DATA_INBOUND_TEMPLATE % (kinesis_stream)
    resource_data_inbound = API_PATH_DATA_INBOUND.replace('/', '')
    resources[resource_data_inbound] = [{
        'httpMethod': 'POST',
        'authorizationType': 'NONE',
        'apiKeyRequired': True,
        'integrations': [{
            'type': 'AWS',
            'uri': 'arn:aws:apigateway:%s:kinesis:action/PutRecords' % DEFAULT_REGION,
            'requestTemplates': {
                'application/json': template_data_inbound
            }
        }],
        'models': {}
    }]
    return aws_stack.create_api_gateway(name=gateway_name, resources=resources,
        stage_name=TEST_STAGE_NAME)


def test_api_gateway_integration():
    # create target Kinesis stream
    aws_stack.create_kinesis_stream(TEST_STREAM_KINESIS_API_GW)

    # create API Gateway and connect it to the target stream
    result = connect_api_gateway_to_kinesis('gateway1', TEST_STREAM_KINESIS_API_GW)

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
