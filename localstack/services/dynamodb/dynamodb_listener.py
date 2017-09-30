import json
import random
import logging
from binascii import crc32
from requests.models import Response
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes, to_str, clone
from localstack.utils.analytics import event_publisher
from localstack.constants import DEFAULT_REGION
from localstack.services.awslambda import lambda_api
from localstack.services.dynamodbstreams import dynamodbstreams_api
from localstack.services.generic_proxy import ProxyListener

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}

# action header prefix
ACTION_PREFIX = 'DynamoDB_20120810'

# set up logger
LOGGER = logging.getLogger(__name__)


class ProxyListenerDynamoDB(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if random.random() < config.DYNAMODB_ERROR_PROBABILITY:
            return error_response_throughput()
        return True

    def return_response(self, method, path, data, headers, response):
        # update table definitions
        if data and 'TableName' in data and 'KeySchema' in data:
            TABLE_DEFINITIONS[data['TableName']] = data

        action = headers.get('X-Amz-Target')
        if not action:
            return

        record = {
            'eventID': '1',
            'eventVersion': '1.0',
            'dynamodb': {
                'StreamViewType': 'NEW_AND_OLD_IMAGES',
                'SequenceNumber': '1',
                'SizeBytes': -1
            },
            'awsRegion': DEFAULT_REGION,
            'eventSource': 'aws:dynamodb'
        }
        records = [record]

        if action == '%s.UpdateItem' % ACTION_PREFIX:
            req = {'TableName': data['TableName'], 'Key': data['Key']}
            new_item = aws_stack.dynamodb_get_item_raw(req)
            if 'Item' not in new_item:
                if 'message' in new_item:
                    ddb_client = aws_stack.connect_to_service('dynamodb')
                    table_names = ddb_client.list_tables()['TableNames']
                    msg = ('Unable to get item from DynamoDB (existing tables: %s): %s' %
                        (table_names, new_item['message']))
                    LOGGER.warning(msg)
                return
            record['eventName'] = 'MODIFY'
            record['dynamodb']['Keys'] = data['Key']
            record['dynamodb']['NewImage'] = new_item['Item']
        elif action == '%s.BatchWriteItem' % ACTION_PREFIX:
            records = []
            for table_name, requests in data['RequestItems'].items():
                for request in requests:
                    put_request = request.get('PutRequest')
                    if put_request:
                        keys = dynamodb_extract_keys(item=put_request['Item'], table_name=table_name)
                        if isinstance(keys, Response):
                            return keys
                        new_record = clone(record)
                        new_record['eventName'] = 'INSERT'
                        new_record['dynamodb']['Keys'] = keys
                        new_record['dynamodb']['NewImage'] = put_request['Item']
                        new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
        elif action == '%s.PutItem' % ACTION_PREFIX:
            record['eventName'] = 'INSERT'
            keys = dynamodb_extract_keys(item=data['Item'], table_name=data['TableName'])
            if isinstance(keys, Response):
                return keys
            record['dynamodb']['Keys'] = keys
            record['dynamodb']['NewImage'] = data['Item']
        elif action == '%s.GetItem' % ACTION_PREFIX:
            if response.status_code == 200:
                content = json.loads(to_str(response.content))
                # make sure we append 'ConsumedCapacity', which is properly
                # returned by dynalite, but not by AWS's DynamoDBLocal
                if 'ConsumedCapacity' not in content and data.get('ReturnConsumedCapacity') in ('TOTAL', 'INDEXES'):
                    content['ConsumedCapacity'] = {
                        'CapacityUnits': 0.5,  # TODO hardcoded
                        'TableName': data['TableName']
                    }
                    response._content = json.dumps(content)
                    response.headers['content-length'] = len(response.content)
                    response.headers['x-amz-crc32'] = calculate_crc32(response)
        elif action == '%s.DeleteItem' % ACTION_PREFIX:
            record['eventName'] = 'REMOVE'
            record['dynamodb']['Keys'] = data['Key']
        elif action == '%s.CreateTable' % ACTION_PREFIX:
            if 'StreamSpecification' in data:
                create_dynamodb_stream(data)
            event_publisher.fire_event(event_publisher.EVENT_DYNAMODB_CREATE_TABLE,
                payload={'n': event_publisher.get_hash(data['TableName'])})
            return
        elif action == '%s.DeleteTable' % ACTION_PREFIX:
            event_publisher.fire_event(event_publisher.EVENT_DYNAMODB_DELETE_TABLE,
                payload={'n': event_publisher.get_hash(data['TableName'])})
            return
        elif action == '%s.UpdateTable' % ACTION_PREFIX:
            if 'StreamSpecification' in data:
                create_dynamodb_stream(data)
            return
        else:
            # nothing to do
            return

        if 'TableName' in data:
            record['eventSourceARN'] = aws_stack.dynamodb_table_arn(data['TableName'])
        forward_to_lambda(records)
        forward_to_ddb_stream(records)


# instantiate listener
UPDATE_DYNAMODB = ProxyListenerDynamoDB()


def calculate_crc32(response):
    return crc32(to_bytes(response.content)) & 0xffffffff


def create_dynamodb_stream(data):
    stream = data['StreamSpecification']
    enabled = stream.get('StreamEnabled')
    if enabled not in [False, 'False']:
        table_name = data['TableName']
        view_type = stream['StreamViewType']
        dynamodbstreams_api.add_dynamodb_stream(table_name=table_name,
            view_type=view_type, enabled=enabled)


def forward_to_lambda(records):
    for record in records:
        sources = lambda_api.get_event_sources(source_arn=record['eventSourceARN'])
        event = {
            'Records': [record]
        }
        for src in sources:
            func_to_call = lambda_api.arn_to_lambda[src['FunctionArn']].function()
            lambda_api.run_lambda(func_to_call, event=event, context={}, func_arn=src['FunctionArn'])


def forward_to_ddb_stream(records):
    dynamodbstreams_api.forward_events(records)


def dynamodb_extract_keys(item, table_name):
    result = {}
    if table_name not in TABLE_DEFINITIONS:
        LOGGER.warning('Unknown table: %s not found in %s' % (table_name, TABLE_DEFINITIONS))
        return None
    for key in TABLE_DEFINITIONS[table_name]['KeySchema']:
        attr_name = key['AttributeName']
        if attr_name not in item:
            return error_response(error_type='ValidationException',
                message='One of the required keys was not given a value')
        result[attr_name] = item[attr_name]
    return result


def error_response(message=None, error_type=None, code=400):
    if not message:
        message = 'Unknown error'
    if not error_type:
        error_type = 'UnknownError'
    if 'com.amazonaws.dynamodb' not in error_type:
        error_type = 'com.amazonaws.dynamodb.v20120810#%s' % error_type
    response = Response()
    response.status_code = code
    content = {
        'message': message,
        '__type': error_type
    }
    response._content = json.dumps(content)
    return response


def error_response_throughput():
    message = ('The level of configured provisioned throughput for the table was exceeded. ' +
            'Consider increasing your provisioning level with the UpdateTable API')
    error_type = 'ProvisionedThroughputExceededException'
    return error_response(message, error_type)
