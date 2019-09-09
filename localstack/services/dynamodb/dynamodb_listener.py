import re
import json
import random
import logging
import threading
from binascii import crc32
from requests.models import Response
from localstack import config
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_bytes, to_str, clone
from localstack.utils.analytics import event_publisher
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener
from localstack.services.dynamodbstreams import dynamodbstreams_api

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}

# action header prefix
ACTION_PREFIX = 'DynamoDB_20120810'

# set up logger
LOGGER = logging.getLogger(__name__)


class ProxyListenerDynamoDB(ProxyListener):
    thread_local = threading.local()

    def __init__(self):
        self._table_ttl_map = {}

    def forward_request(self, method, path, data, headers):
        if path.startswith('/shell'):
            return True
        data = json.loads(to_str(data))
        ddb_client = aws_stack.connect_to_service('dynamodb')

        if random.random() < config.DYNAMODB_ERROR_PROBABILITY:
            return error_response_throughput()

        action = headers.get('X-Amz-Target')
        if action == '%s.CreateTable' % ACTION_PREFIX:
            # Check if table exists, to avoid error log output from DynamoDBLocal
            table_names = ddb_client.list_tables()['TableNames']
            if to_str(data['TableName']) in table_names:
                return 200
        elif action in ('%s.PutItem' % ACTION_PREFIX, '%s.UpdateItem' % ACTION_PREFIX, '%s.DeleteItem' % ACTION_PREFIX):
            # find an existing item and store it in a thread-local, so we can access it in return_response,
            # in order to determine whether an item already existed (MODIFY) or not (INSERT)
            ProxyListenerDynamoDB.thread_local.existing_item = find_existing_item(data)
        elif action == '%s.DescribeTable' % ACTION_PREFIX:
            # Check if table exists, to avoid error log output from DynamoDBLocal
            table_names = ddb_client.list_tables()['TableNames']
            if to_str(data['TableName']) not in table_names:
                response = error_response(message='Cannot do operations on a non-existent table',
                                          error_type='ResourceNotFoundException')
                fix_headers_for_updated_response(response)
                return response
        elif action == '%s.DeleteTable' % ACTION_PREFIX:
            # Check if table exists, to avoid error log output from DynamoDBLocal
            table_names = ddb_client.list_tables()['TableNames']
            if to_str(data['TableName']) not in table_names:
                response = error_response(message='Cannot do operations on a non-existent table',
                                          error_type='ResourceNotFoundException')
                fix_headers_for_updated_response(response)
                return response
        elif action == '%s.BatchWriteItem' % ACTION_PREFIX:
            existing_items = []
            for table_name in sorted(data['RequestItems'].keys()):
                for request in data['RequestItems'][table_name]:
                    for key in ['PutRequest', 'DeleteRequest']:
                        inner_request = request.get(key)
                        if inner_request:
                            existing_items.append(find_existing_item(inner_request, table_name))
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items
        elif action == '%s.TransactWriteItems' % ACTION_PREFIX:
            existing_items = []
            for item in data['TransactItems']:
                for key in ['Put', 'Update', 'Delete']:
                    inner_item = item.get(key)
                    if inner_item:
                        existing_items.append(find_existing_item(inner_item))
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items
        elif action == '%s.UpdateTimeToLive' % ACTION_PREFIX:
            # TODO: TTL status is maintained/mocked but no real expiry is happening for items
            response = Response()
            response.status_code = 200
            self._table_ttl_map[data['TableName']] = {
                'AttributeName': data['TimeToLiveSpecification']['AttributeName'],
                'Status': data['TimeToLiveSpecification']['Enabled']
            }
            response._content = json.dumps({'TimeToLiveSpecification': data['TimeToLiveSpecification']})
            fix_headers_for_updated_response(response)
            return response
        elif action == '%s.DescribeTimeToLive' % ACTION_PREFIX:
            response = Response()
            response.status_code = 200
            if data['TableName'] in self._table_ttl_map:
                if self._table_ttl_map[data['TableName']]['Status']:
                    ttl_status = 'ENABLED'
                else:
                    ttl_status = 'DISABLED'
                response._content = json.dumps({
                    'TimeToLiveDescription': {
                        'AttributeName': self._table_ttl_map[data['TableName']]['AttributeName'],
                        'TimeToLiveStatus': ttl_status
                    }
                })
            else:  # TTL for dynamodb table not set
                response._content = json.dumps({'TimeToLiveDescription': {'TimeToLiveStatus': 'DISABLED'}})
            fix_headers_for_updated_response(response)
            return response
        elif action == '%s.TagResource' % ACTION_PREFIX or action == '%s.UntagResource' % ACTION_PREFIX:
            response = Response()
            response.status_code = 200
            response._content = ''  # returns an empty body on success.
            fix_headers_for_updated_response(response)
            return response
        elif action == '%s.ListTagsOfResource' % ACTION_PREFIX:
            response = Response()
            response.status_code = 200
            response._content = json.dumps({'Tags': []})  # TODO: mocked and returns an empty list of tags for now.
            fix_headers_for_updated_response(response)
            return response

        return True

    def return_response(self, method, path, data, headers, response):
        if path.startswith('/shell'):
            return
        data = json.loads(to_str(data))

        # update table definitions
        if data and 'TableName' in data and 'KeySchema' in data:
            TABLE_DEFINITIONS[data['TableName']] = data

        if response._content:
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:aws:dynamodb:' +
            'ddblocal:([^"]+)"', r'\1: "arn:aws:dynamodb:%s:\2"' % aws_stack.get_local_region(),
            to_str(response._content))
            if content_replaced != response._content:
                response._content = content_replaced
                fix_headers_for_updated_response(response)

        action = headers.get('X-Amz-Target')
        if not action:
            return

        record = {
            'eventID': '1',
            'eventVersion': '1.0',
            'dynamodb': {
                'StreamViewType': 'NEW_AND_OLD_IMAGES',
                'SizeBytes': -1
            },
            'awsRegion': config.DEFAULT_REGION,
            'eventSource': 'aws:dynamodb'
        }
        records = [record]

        if action == '%s.UpdateItem' % ACTION_PREFIX:
            if response.status_code == 200:
                updated_item = find_existing_item(data)
                if not updated_item:
                    return
                record['eventName'] = 'MODIFY'
                record['dynamodb']['Keys'] = data['Key']
                record['dynamodb']['OldImage'] = self._thread_local('existing_item')
                record['dynamodb']['NewImage'] = updated_item
                record['dynamodb']['SizeBytes'] = len(json.dumps(updated_item))
        elif action == '%s.BatchWriteItem' % ACTION_PREFIX:
            records = self.prepare_batch_write_item_records(record, data)
        elif action == '%s.TransactWriteItems' % ACTION_PREFIX:
            records = self.prepare_transact_write_item_records(record, data)
        elif action == '%s.PutItem' % ACTION_PREFIX:
            if response.status_code == 200:
                existing_item = self._thread_local('existing_item')
                record['eventName'] = 'INSERT' if not existing_item else 'MODIFY'
                keys = dynamodb_extract_keys(item=data['Item'], table_name=data['TableName'])
                if isinstance(keys, Response):
                    return keys
                record['dynamodb']['Keys'] = keys
                record['dynamodb']['NewImage'] = data['Item']
                record['dynamodb']['SizeBytes'] = len(json.dumps(data['Item']))
                if existing_item:
                    record['dynamodb']['OldImage'] = existing_item
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
                    fix_headers_for_updated_response(response)
        elif action == '%s.DeleteItem' % ACTION_PREFIX:
            if response.status_code == 200:
                old_item = self._thread_local('existing_item')
                record['eventName'] = 'REMOVE'
                record['dynamodb']['Keys'] = data['Key']
                record['dynamodb']['OldImage'] = old_item
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

        if len(records) > 0 and 'eventName' in records[0]:
            if 'TableName' in data:
                records[0]['eventSourceARN'] = aws_stack.dynamodb_table_arn(data['TableName'])
            forward_to_lambda(records)
            forward_to_ddb_stream(records)

    def prepare_batch_write_item_records(self, record, data):
        records = []
        i = 0
        for table_name in sorted(data['RequestItems'].keys()):
            for request in data['RequestItems'][table_name]:
                put_request = request.get('PutRequest')
                if put_request:
                    existing_item = self._thread_local('existing_items')[i]
                    keys = dynamodb_extract_keys(item=put_request['Item'], table_name=table_name)
                    if isinstance(keys, Response):
                        return keys
                    new_record = clone(record)
                    new_record['eventName'] = 'INSERT' if not existing_item else 'MODIFY'
                    new_record['dynamodb']['Keys'] = keys
                    new_record['dynamodb']['NewImage'] = put_request['Item']
                    if existing_item:
                        new_record['dynamodb']['OldImage'] = existing_item
                    new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                    records.append(new_record)
                delete_request = request.get('DeleteRequest')
                if delete_request:
                    keys = delete_request['Key']
                    if isinstance(keys, Response):
                        return keys
                    new_record = clone(record)
                    new_record['eventName'] = 'REMOVE'
                    new_record['dynamodb']['Keys'] = keys
                    new_record['dynamodb']['OldImage'] = self._thread_local('existing_items')[i]
                    new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                    records.append(new_record)
                i += 1
        return records

    def prepare_transact_write_item_records(self, record, data):
        records = []
        for i, request in enumerate(data['TransactItems']):
            put_request = request.get('Put')
            if put_request:
                existing_item = self._thread_local('existing_items')[i]
                table_name = put_request['TableName']
                keys = dynamodb_extract_keys(item=put_request['Item'], table_name=table_name)
                if isinstance(keys, Response):
                    return keys
                new_record = clone(record)
                new_record['eventName'] = 'INSERT' if not existing_item else 'MODIFY'
                new_record['dynamodb']['Keys'] = keys
                new_record['dynamodb']['NewImage'] = put_request['Item']
                if existing_item:
                    new_record['dynamodb']['OldImage'] = existing_item
                new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
            update_request = request.get('Update')
            if update_request:
                table_name = update_request['TableName']
                keys = update_request['Key']
                if isinstance(keys, Response):
                    return keys
                updated_item = find_existing_item(update_request, table_name)
                if not updated_item:
                    return
                new_record = clone(record)
                new_record['eventName'] = 'MODIFY'
                new_record['dynamodb']['Keys'] = keys
                new_record['dynamodb']['OldImage'] = self._thread_local('existing_items')[i]
                new_record['dynamodb']['NewImage'] = updated_item
                new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
            delete_request = request.get('Delete')
            if delete_request:
                table_name = delete_request['TableName']
                keys = delete_request['Key']
                if isinstance(keys, Response):
                    return keys
                new_record = clone(record)
                new_record['eventName'] = 'REMOVE'
                new_record['dynamodb']['Keys'] = keys
                new_record['dynamodb']['OldImage'] = self._thread_local('existing_items')[i]
                new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
        return records

    def _thread_local(self, name, default=None):
        try:
            return getattr(ProxyListenerDynamoDB.thread_local, name)
        except AttributeError:
            return default


# instantiate listener
UPDATE_DYNAMODB = ProxyListenerDynamoDB()


def find_existing_item(put_item, table_name=None):
    table_name = table_name or put_item['TableName']
    ddb_client = aws_stack.connect_to_service('dynamodb')

    search_key = {}
    if 'Key' in put_item:
        search_key = put_item['Key']
    else:
        schema = ddb_client.describe_table(TableName=table_name)
        schemas = [schema['Table']['KeySchema']]
        for index in schema['Table'].get('GlobalSecondaryIndexes', []):
            # schemas.append(index['KeySchema'])
            pass
        for schema in schemas:
            for key in schema:
                key_name = key['AttributeName']
                search_key[key_name] = put_item['Item'][key_name]
        if not search_key:
            return

    req = {'TableName': table_name, 'Key': search_key}
    existing_item = aws_stack.dynamodb_get_item_raw(req)
    if 'Item' not in existing_item:
        if 'message' in existing_item:
            table_names = ddb_client.list_tables()['TableNames']
            msg = ('Unable to get item from DynamoDB (existing tables: %s): %s' %
                (table_names, existing_item['message']))
            LOGGER.warning(msg)
        return
    return existing_item.get('Item')


def fix_headers_for_updated_response(response):
    response.headers['content-length'] = len(to_bytes(response.content))
    response.headers['x-amz-crc32'] = calculate_crc32(response)


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
            lambda_api.run_lambda(event=event, context={}, func_arn=src['FunctionArn'])


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
