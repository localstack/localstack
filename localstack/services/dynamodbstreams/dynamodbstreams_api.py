import json
from flask import Flask, jsonify, request, make_response
from localstack.services import generic_proxy
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str

APP_NAME = 'ddb_streams_api'

app = Flask(APP_NAME)

DDB_STREAMS = {}

DDB_KINESIS_STREAM_NAME_PREFIX = '__ddb_stream_'

ACTION_HEADER_PREFIX = 'DynamoDBStreams_20120810'


def add_dynamodb_stream(table_name, view_type='NEW_AND_OLD_IMAGES', enabled=True):
    if enabled:
        # create kinesis stream as a backend
        stream_name = get_kinesis_stream_name(table_name)
        aws_stack.create_kinesis_stream(stream_name)
        stream = {
            'StreamArn': aws_stack.dynamodb_stream_arn(table_name=table_name),
            'TableName': table_name,
            'StreamLabel': 'TODO',
            'StreamStatus': 'ENABLED',
            'KeySchema': [],
            'Shards': []
        }
        table_arn = aws_stack.dynamodb_table_arn(table_name)
        DDB_STREAMS[table_arn] = stream


def forward_events(records):
    kinesis = aws_stack.connect_to_service('kinesis')
    for record in records:
        table_arn = record['eventSourceARN']
        stream = DDB_STREAMS.get(table_arn)
        if stream:
            table_name = table_name_from_stream_arn(stream['StreamArn'])
            stream_name = get_kinesis_stream_name(table_name)
            kinesis.put_record(StreamName=stream_name, Data=json.dumps(record), PartitionKey='TODO')


@app.route('/', methods=['POST'])
def post_request():
    action = request.headers.get('x-amz-target')
    data = json.loads(to_str(request.data))
    result = {}
    kinesis = aws_stack.connect_to_service('kinesis')
    if action == '%s.ListStreams' % ACTION_HEADER_PREFIX:
        result = {
            'Streams': list(DDB_STREAMS.values()),
            'LastEvaluatedStreamArn': 'TODO'
        }
    elif action == '%s.DescribeStream' % ACTION_HEADER_PREFIX:
        for stream in DDB_STREAMS.values():
            if stream['StreamArn'] == data['StreamArn']:
                result = {
                    'StreamDescription': stream
                }
                # get stream details
                dynamodb = aws_stack.connect_to_service('dynamodb')
                table_name = table_name_from_stream_arn(stream['StreamArn'])
                stream_name = get_kinesis_stream_name(table_name)
                stream_details = kinesis.describe_stream(StreamName=stream_name)
                table_details = dynamodb.describe_table(TableName=table_name)
                stream['KeySchema'] = table_details['Table']['KeySchema']
                stream['Shards'] = stream_details['StreamDescription']['Shards']
                break
        if not result:
            return error_response('Requested resource not found', error_type='ResourceNotFoundException')
    elif action == '%s.GetShardIterator' % ACTION_HEADER_PREFIX:
        # forward request to Kinesis API
        stream_name = stream_name_from_stream_arn(data['StreamArn'])
        result = kinesis.get_shard_iterator(StreamName=stream_name,
            ShardId=data['ShardId'], ShardIteratorType=data['ShardIteratorType'])
    elif action == '%s.GetRecords' % ACTION_HEADER_PREFIX:
        kinesis_records = kinesis.get_records(**data)
        result = {'Records': []}
        for record in kinesis_records['Records']:
            result['Records'].append(json.loads(to_str(record['Data'])))
    else:
        print('WARNING: Unknown operation "%s"' % action)
    return jsonify(result)


# -----------------
# HELPER FUNCTIONS
# -----------------

def error_response(message=None, error_type=None, code=400):
    if not message:
        message = 'Unknown error'
    if not error_type:
        error_type = 'UnknownError'
    if 'com.amazonaws.dynamodb' not in error_type:
        error_type = 'com.amazonaws.dynamodb.v20120810#%s' % error_type
    content = {
        'message': message,
        '__type': error_type
    }
    return make_response(jsonify(content), code)


def get_kinesis_stream_name(table_name):
    return DDB_KINESIS_STREAM_NAME_PREFIX + table_name


def table_name_from_stream_arn(stream_arn):
    return stream_arn.split(':table/')[1].split('/')[0]


def stream_name_from_stream_arn(stream_arn):
    table_name = table_name_from_stream_arn(stream_arn)
    return get_kinesis_stream_name(table_name)


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
