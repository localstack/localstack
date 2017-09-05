import json
import base64
from localstack.utils.aws.aws_stack import render_velocity_template
from localstack.utils.common import to_str


# template used to transform incoming requests at the API Gateway (forward to Kinesis)
APIGATEWAY_TRANSFORMATION_TEMPLATE = """{
    "StreamName": "stream-1",
    "Records": [
        #set( $numRecords = $input.path('$.records').size() )
        #if($numRecords > 0)
        #set( $maxIndex = $numRecords - 1 )
        #foreach( $idx in [0..$maxIndex] )
        #set( $elem = $input.path("$.records[${idx}]") )
        #set( $elemJsonB64 = $util.base64Encode($input.json("$.records[${idx}].data")) )
        {
            "Data": "$elemJsonB64",
            "PartitionKey": #if( $elem.partitionKey != '')"$elem.partitionKey"
                            #else"$elemJsonB64.length()"#end
        }#if($foreach.hasNext),#end
        #end
        #end
    ]
}"""


def test_array_size():
    template = "#set($list = $input.path('$.records')) $list.size()"
    context = {
        'records': [{
            'data': {'foo': 'bar1'}
        }, {
            'data': {'foo': 'bar2'}
        }]
    }
    result = render_velocity_template(template, context)
    assert(result == ' 2')
    result = render_velocity_template(template, json.dumps(context))
    assert(result == ' 2')


def test_message_transformation():
    template = APIGATEWAY_TRANSFORMATION_TEMPLATE
    records = [
        {
            'data': {
                'foo': 'foo1',
                'bar': 'bar2'
            }
        },
        {
            'data': {
                'foo': 'foo1',
                'bar': 'bar2'
            },
            'partitionKey': 'key123'
        }
    ]
    context = {
        'records': records
    }
    # try rendering the template
    result = render_velocity_template(template, context, as_json=True)
    result_decoded = json.loads(to_str(base64.b64decode(result['Records'][0]['Data'])))
    assert result_decoded == records[0]['data']
    assert len(result['Records'][0]['PartitionKey']) > 0
    assert result['Records'][1]['PartitionKey'] == 'key123'
    # try again with context as string
    context = json.dumps(context)
    result = render_velocity_template(template, context, as_json=True)
    result_decoded = json.loads(to_str(base64.b64decode(result['Records'][0]['Data'])))
    assert result_decoded == records[0]['data']
    assert len(result['Records'][0]['PartitionKey']) > 0
    assert result['Records'][1]['PartitionKey'] == 'key123'

    # test with empty array
    records = []
    context = {
        'records': records
    }
    # try rendering the template
    result = render_velocity_template(template, context, as_json=True)
    assert result['Records'] == []
