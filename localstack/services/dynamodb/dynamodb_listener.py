import json
import random
import logging
from requests.models import Response
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import *
from localstack.constants import *
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodbstreams import dynamodbstreams_api

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}

# set up logger
LOGGER = logging.getLogger(__name__)


def update_dynamodb(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:
        if random.random() < config.DYNAMODB_ERROR_PROBABILITY:
            return dynamodb_error_response(data)
        return True

    # update table definitions
    if data and 'TableName' in data and 'KeySchema' in data:
        TABLE_DEFINITIONS[data['TableName']] = data

    action = headers.get('X-Amz-Target')
    if not action:
        return

    response_data = json.loads(to_str(response.content))
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
    records = [record]

    if action == 'DynamoDB_20120810.UpdateItem':
        req = {'TableName': data['TableName'], 'Key': data['Key']}
        new_item = aws_stack.dynamodb_get_item_raw(req)
        if 'Item' not in new_item:
            if 'message' in new_item:
                ddb_client = aws_stack.connect_to_service('dynamodb')
                table_names = ddb_client.list_tables()['TableNames']
                msg = 'Unable to get item from DynamoDB (existing tables: %s): %s' % (table_names, new_item['message'])
                LOGGER.warning(msg)
            return
        record['eventName'] = 'MODIFY'
        record['dynamodb']['Keys'] = data['Key']
        record['dynamodb']['NewImage'] = new_item['Item']
    elif action == 'DynamoDB_20120810.BatchWriteItem':
        records = []
        for table_name, requests in data['RequestItems'].items():
            for request in requests:
                put_request = request.get('PutRequest')
                if put_request:
                    keys = dynamodb_extract_keys(item=put_request['Item'], table_name=table_name)
                    new_record = clone(record)
                    new_record['eventName'] = 'INSERT'
                    new_record['dynamodb']['Keys'] = keys
                    new_record['dynamodb']['NewImage'] = put_request['Item']
                    new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                    records.append(new_record)
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
            enabled = stream.get('StreamEnabled')
            if enabled not in [False, 'False']:
                table_name = data['TableName']
                view_type = stream['StreamViewType']
                dynamodbstreams_api.add_dynamodb_stream(table_name=table_name,
                    view_type=view_type, enabled=enabled)
        return
    else:
        # nothing to do
        return

    if 'TableName' in data:
        record['eventSourceARN'] = aws_stack.dynamodb_table_arn(data['TableName'])
    forward_to_lambda(records)
    forward_to_ddb_stream(records)


def forward_to_lambda(records):
    for record in records:
        sources = lambda_api.get_event_sources(source_arn=record['eventSourceARN'])
        event = {
            'Records': [record]
        }
        for src in sources:
            func_to_call = lambda_api.lambda_arn_to_function[src['FunctionArn']]
            lambda_api.run_lambda(func_to_call, event=event, context={}, func_arn=src['FunctionArn'])


def forward_to_ddb_stream(records):
    dynamodbstreams_api.forward_events(records)


def dynamodb_extract_keys(item, table_name):
    result = {}
    if table_name not in TABLE_DEFINITIONS:
        LOGGER.warning("Unknown table: %s not found in %s" % (table_name, TABLE_DEFINITIONS))
        return None
    for key in TABLE_DEFINITIONS[table_name]['KeySchema']:
        attr_name = key['AttributeName']
        result[attr_name] = item[attr_name]
    return result


def dynamodb_error_response(data):
    error_response = Response()
    error_response.status_code = 400
    content = {
        'message': ('The level of configured provisioned throughput for the table was exceeded. ' +
            'Consider increasing your provisioning level with the UpdateTable API'),
        '__type': 'com.amazonaws.dynamodb.v20120810#ProvisionedThroughputExceededException'
    }
    error_response._content = json.dumps(content)
    return error_response
