import json
from localstack.utils.aws import aws_stack
from localstack.utils.common import *
from localstack.config import TEST_DYNAMODB_URL
from localstack.constants import *
from localstack.mock.apis import lambda_api, dynamodbstreams_api

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}


def update_dynamodb(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        return True

    # update table definitions
    if data and 'TableName' in data and 'KeySchema' in data:
        TABLE_DEFINITIONS[data['TableName']] = data

    action = headers.get('X-Amz-Target')
    if not action:
        return

    response_data = json.loads(response.text)
    record = {
        "eventID": "1",
        "eventVersion": "1.0",
        "dynamodb": {
            "StreamViewType": "NEW_AND_OLD_IMAGES",
            "SequenceNumber": "1",
            "SizeBytes": -1
        },
        "awsRegion": DEFAULT_REGION,
        "eventSource": "aws:dynamodb"
    }
    event = {
        'Records': [record]
    }

    if action == 'DynamoDB_20120810.UpdateItem':
        req = {'TableName': data['TableName']}
        req['Key'] = data['Key']
        new_item = aws_stack.dynamodb_get_item_raw(TEST_DYNAMODB_URL, req)
        if 'Item' not in new_item:
            if 'message' in new_item:
                print('WARNING: Unable to get item from DynamoDB: %s' % new_item['message'])
            return
        record['eventName'] = 'MODIFY'
        record['dynamodb']['Keys'] = data['Key']
        record['dynamodb']['NewImage'] = new_item['Item']
    elif action == 'DynamoDB_20120810.PutItem':
        record['eventName'] = 'INSERT'
        keys = dynamodb_extract_keys(item=data['Item'], table_name=data['TableName'])
        record['dynamodb']['Keys'] = keys
        record['dynamodb']['NewImage'] = data['Item']
    elif action == 'DynamoDB_20120810.DeleteItem':
        record['eventName'] = 'REMOVE'
        record['dynamodb']['Keys'] = data['Key']
    elif action == 'DynamoDB_20120810.CreateTable':
        if 'StreamSpecification' in data:
            stream = data['StreamSpecification']
            enabled = stream['StreamEnabled']
            if enabled:
                table_name = data['TableName']
                view_type = stream['StreamViewType']
                dynamodbstreams_api.add_dynamodb_stream(table_name=table_name,
                    view_type=view_type, enabled=enabled)
        return
    else:
        # nothing to do
        return
    record['eventSourceARN'] = aws_stack.dynamodb_table_arn(data['TableName'])
    sources = lambda_api.get_event_sources(source_arn=record['eventSourceARN'])
    if len(sources) > 0:
        pass
    for src in sources:
        func_to_call = lambda_api.lambda_arn_to_function[src['FunctionArn']]
        lambda_api.run_lambda(func_to_call, event=event, context={})


def dynamodb_extract_keys(item, table_name):
    result = {}
    if table_name not in TABLE_DEFINITIONS:
        print("WARN: unknown table: %s not found in %s" % (table_name, TABLE_DEFINITIONS))
        return None
    for key in TABLE_DEFINITIONS[table_name]['KeySchema']:
        attr_name = key['AttributeName']
        result[attr_name] = item[attr_name]
    return result
