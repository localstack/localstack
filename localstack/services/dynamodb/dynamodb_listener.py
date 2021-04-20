import re
import json
import random
import logging
import threading
import time
import traceback
from binascii import crc32
from cachetools import TTLCache
from requests.models import Request, Response
from localstack import config, constants
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.common import to_bytes, to_str, clone, select_attributes, short_uid
from localstack.utils.analytics import event_publisher
from localstack.utils.bootstrap import is_api_enabled
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import ProxyListener
from localstack.services.dynamodbstreams import dynamodbstreams_api

# set up logger
LOGGER = logging.getLogger(__name__)

# cache schema definitions
SCHEMA_CACHE = TTLCache(maxsize=50, ttl=20)

# cache table definitions - used for testing
TABLE_DEFINITIONS = {}

# cache table taggings
TABLE_TAGS = {}

# action header prefix
ACTION_PREFIX = 'DynamoDB_20120810.'

# maps global table names to configurations
GLOBAL_TABLES = {}

# list of actions subject to throughput limitations
READ_THROTTLED_ACTIONS = [
    'GetItem', 'Query', 'Scan', 'TransactGetItems', 'BatchGetItem'
]
WRITE_THROTTLED_ACTIONS = [
    'PutItem', 'BatchWriteItem', 'UpdateItem', 'DeleteItem', 'TransactWriteItems',
]
THROTTLED_ACTIONS = READ_THROTTLED_ACTIONS + WRITE_THROTTLED_ACTIONS


class ProxyListenerDynamoDB(ProxyListener):
    thread_local = threading.local()

    def __init__(self):
        self._table_ttl_map = {}

    @staticmethod
    def table_exists(ddb_client, table_name):
        paginator = ddb_client.get_paginator('list_tables')
        pages = paginator.paginate(
            PaginationConfig={
                'PageSize': 100
            }
        )
        for page in pages:
            table_names = page['TableNames']
            if to_str(table_name) in table_names:
                return True
        return False

    def action_should_throttle(self, action, actions):
        throttled = ['%s%s' % (ACTION_PREFIX, a) for a in actions]
        return (action in throttled) or (action in actions)

    def should_throttle(self, action):
        rand = random.random()
        if (rand < config.DYNAMODB_READ_ERROR_PROBABILITY and
                self.action_should_throttle(action, READ_THROTTLED_ACTIONS)):
            return True
        elif (rand < config.DYNAMODB_WRITE_ERROR_PROBABILITY and
                self.action_should_throttle(action, WRITE_THROTTLED_ACTIONS)):
            return True
        elif (rand < config.DYNAMODB_ERROR_PROBABILITY and
                self.action_should_throttle(action, THROTTLED_ACTIONS)):
            return True
        else:
            return False

    def forward_request(self, method, path, data, headers):
        result = handle_special_request(method, path, data, headers)
        if result is not None:
            return result

        # prepare request headers
        self.prepare_request_headers(headers)

        data_orig = data
        data = data or '{}'
        data = json.loads(to_str(data))
        ddb_client = aws_stack.connect_to_service('dynamodb')
        action = headers.get('X-Amz-Target', '')
        action = action.replace(ACTION_PREFIX, '')

        if self.should_throttle(action) and (not action == 'BatchWriteItem'):
            return error_response_throughput()

        ProxyListenerDynamoDB.thread_local.existing_item = None

        if action == 'CreateTable':
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if self.table_exists(ddb_client, data['TableName']):
                return error_response(message='Table already created',
                                      error_type='ResourceInUseException', code=400)

        elif action == 'CreateGlobalTable':
            return create_global_table(data)

        elif action == 'DescribeGlobalTable':
            return describe_global_table(data)

        elif action == 'ListGlobalTables':
            return list_global_tables(data)

        elif action == 'UpdateGlobalTable':
            return update_global_table(data)

        elif action in ('PutItem', 'UpdateItem', 'DeleteItem'):
            # find an existing item and store it in a thread-local, so we can access it in return_response,
            # in order to determine whether an item already existed (MODIFY) or not (INSERT)
            try:
                if has_event_sources_or_streams_enabled(data['TableName']):
                    ProxyListenerDynamoDB.thread_local.existing_item = find_existing_item(data)
            except Exception as e:
                if 'ResourceNotFoundException' in str(e):
                    return get_table_not_found_error()
                raise

            # Fix incorrect values if ReturnValues==ALL_OLD and ReturnConsumedCapacity is
            # empty, see https://github.com/localstack/localstack/issues/2049
            if ((data.get('ReturnValues') == 'ALL_OLD') or (not data.get('ReturnValues'))) \
                    and not data.get('ReturnConsumedCapacity'):
                data['ReturnConsumedCapacity'] = 'TOTAL'
                return Request(data=json.dumps(data), method=method, headers=headers)

        elif action == 'DescribeTable':
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data['TableName']):
                return get_table_not_found_error()

        elif action == 'DeleteTable':
            # Check if table exists, to avoid error log output from DynamoDBLocal
            if not self.table_exists(ddb_client, data['TableName']):
                return get_table_not_found_error()

        elif action == 'BatchWriteItem':
            existing_items = []
            unprocessed_items = []
            for table_name in sorted(data['RequestItems'].keys()):
                for request in data['RequestItems'][table_name]:
                    for key in ['PutRequest', 'DeleteRequest']:
                        inner_request = request.get(key)
                        if inner_request:
                            if self.should_throttle(action):
                                unprocessed_items.append(inner_request)
                            else:
                                item = find_existing_item(inner_request, table_name)
                                existing_items.append(item)
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items
            ProxyListenerDynamoDB.thread_local.unprocessed_items = unprocessed_items

        elif action == 'Query':
            if data.get('IndexName'):
                if not is_index_query_valid(to_str(data['TableName']), data.get('Select')):
                    return error_response(
                        message='One or more parameter values were invalid: Select type ALL_ATTRIBUTES '
                                'is not supported for global secondary index id-index because its projection '
                                'type is not ALL', error_type='ValidationException', code=400)

        elif action == 'TransactWriteItems':
            existing_items = []
            for item in data['TransactItems']:
                for key in ['Put', 'Update', 'Delete']:
                    inner_item = item.get(key)
                    if inner_item:
                        existing_items.append(find_existing_item(inner_item))
            ProxyListenerDynamoDB.thread_local.existing_items = existing_items

        elif action == 'UpdateTimeToLive':
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

        elif action == 'DescribeTimeToLive':
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

        elif action in ('TagResource', 'UntagResource'):
            response = Response()
            response.status_code = 200
            response._content = ''  # returns an empty body on success.
            fix_headers_for_updated_response(response)
            return response

        elif action == 'ListTagsOfResource':
            response = Response()
            response.status_code = 200
            response._content = json.dumps({
                'Tags': [
                    {'Key': k, 'Value': v}
                    for k, v in TABLE_TAGS.get(data['ResourceArn'], {}).items()
                ]
            })
            fix_headers_for_updated_response(response)
            return response

        return Request(data=data_orig, method=method, headers=headers)

    def return_response(self, method, path, data, headers, response):
        if path.startswith('/shell') or method == 'GET':
            return

        data = json.loads(to_str(data))

        # update table definitions
        if data and 'TableName' in data and 'KeySchema' in data:
            TABLE_DEFINITIONS[data['TableName']] = data

        if response._content:
            # fix the table and latest stream ARNs (DynamoDBLocal hardcodes "ddblocal" as the region)
            content_replaced = re.sub(
                r'("TableArn"|"LatestStreamArn"|"StreamArn")\s*:\s*"arn:aws:dynamodb:ddblocal:([^"]+)"',
                r'\1: "arn:aws:dynamodb:%s:\2"' % aws_stack.get_region(),
                to_str(response._content)
            )
            if content_replaced != response._content:
                response._content = content_replaced
                fix_headers_for_updated_response(response)

        action = headers.get('X-Amz-Target', '')
        action = action.replace(ACTION_PREFIX, '')
        if not action:
            return
        # upgrade event version to 1.1
        record = {
            'eventID': '1',
            'eventVersion': '1.1',
            'dynamodb': {
                'ApproximateCreationDateTime': time.time(),
                'StreamViewType': 'NEW_AND_OLD_IMAGES',
                'SizeBytes': -1
            },
            'awsRegion': aws_stack.get_region(),
            'eventSource': 'aws:dynamodb'
        }
        records = [record]

        streams_enabled_cache = {}
        table_name = data.get('TableName')
        event_sources_or_streams_enabled = has_event_sources_or_streams_enabled(table_name, streams_enabled_cache)

        if action == 'UpdateItem':
            if response.status_code == 200 and event_sources_or_streams_enabled:
                existing_item = self._thread_local('existing_item')
                record['eventName'] = 'INSERT' if not existing_item else 'MODIFY'
                record['eventID'] = short_uid()
                updated_item = find_existing_item(data)
                if not updated_item:
                    return
                record['dynamodb']['Keys'] = data['Key']
                if existing_item:
                    record['dynamodb']['OldImage'] = existing_item
                record['dynamodb']['NewImage'] = updated_item
                record['dynamodb']['SizeBytes'] = len(json.dumps(updated_item))
                stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                if stream_spec:
                    record['dynamodb']['StreamViewType'] = stream_spec['StreamViewType']

        elif action == 'BatchWriteItem':
            records, unprocessed_items = self.prepare_batch_write_item_records(record, data)
            for record in records:
                event_sources_or_streams_enabled = (event_sources_or_streams_enabled or
                    has_event_sources_or_streams_enabled(record['eventSourceARN'], streams_enabled_cache))
            if response.status_code == 200 and len(unprocessed_items) > 0:
                content = json.loads(to_str(response.content))
                table_name = list(data['RequestItems'].keys())[0]
                if table_name not in content['UnprocessedItems']:
                    content['UnprocessedItems'][table_name] = []
                for unprocessed_item in unprocessed_items:
                    content['UnprocessedItems'][table_name].append(unprocessed_item)
                response._content = json.dumps(content)
                fix_headers_for_updated_response(response)

        elif action == 'TransactWriteItems':
            records = self.prepare_transact_write_item_records(record, data)
            for record in records:
                event_sources_or_streams_enabled = (event_sources_or_streams_enabled or
                    has_event_sources_or_streams_enabled(record['eventSourceARN'], streams_enabled_cache))

        elif action == 'PutItem':
            if response.status_code == 200:
                keys = dynamodb_extract_keys(item=data['Item'], table_name=table_name)
                if isinstance(keys, Response):
                    return keys
                # fix response
                if response._content == '{}':
                    response._content = update_put_item_response_content(data, response._content)
                    fix_headers_for_updated_response(response)
                if event_sources_or_streams_enabled:
                    existing_item = self._thread_local('existing_item')
                    # Get stream specifications details for the table
                    stream_spec = dynamodb_get_table_stream_specification(table_name=table_name)
                    record['eventName'] = 'INSERT' if not existing_item else 'MODIFY'
                    # prepare record keys
                    record['dynamodb']['Keys'] = keys
                    record['dynamodb']['NewImage'] = data['Item']
                    record['dynamodb']['SizeBytes'] = len(json.dumps(data['Item']))
                    record['eventID'] = short_uid()
                    if stream_spec:
                        record['dynamodb']['StreamViewType'] = stream_spec['StreamViewType']
                    if existing_item:
                        record['dynamodb']['OldImage'] = existing_item

        elif action in ('GetItem', 'Query'):
            if response.status_code == 200:
                content = json.loads(to_str(response.content))
                # make sure we append 'ConsumedCapacity', which is properly
                # returned by dynalite, but not by AWS's DynamoDBLocal
                if 'ConsumedCapacity' not in content and data.get('ReturnConsumedCapacity') in ['TOTAL', 'INDEXES']:
                    content['ConsumedCapacity'] = {
                        'TableName': table_name,
                        'CapacityUnits': 5,             # TODO hardcoded
                        'ReadCapacityUnits': 2,
                        'WriteCapacityUnits': 3
                    }
                    response._content = json.dumps(content)
                    fix_headers_for_updated_response(response)

        elif action == 'DeleteItem':
            if response.status_code == 200 and event_sources_or_streams_enabled:
                old_item = self._thread_local('existing_item')
                record['eventName'] = 'REMOVE'
                record['dynamodb']['Keys'] = data['Key']
                record['dynamodb']['OldImage'] = old_item

        elif action == 'CreateTable':
            if 'StreamSpecification' in data:
                if response.status_code == 200:
                    content = json.loads(to_str(response._content))
                    create_dynamodb_stream(data, content['TableDescription'].get('LatestStreamLabel'))

            event_publisher.fire_event(event_publisher.EVENT_DYNAMODB_CREATE_TABLE,
                payload={'n': event_publisher.get_hash(table_name)})

            if data.get('Tags') and response.status_code == 200:
                table_arn = json.loads(response._content)['TableDescription']['TableArn']
                TABLE_TAGS[table_arn] = {tag['Key']: tag['Value'] for tag in data['Tags']}

            return

        elif action == 'DeleteTable':
            if response.status_code == 200:
                table_arn = json.loads(response._content).get('TableDescription', {}).get('TableArn')
                event_publisher.fire_event(
                    event_publisher.EVENT_DYNAMODB_DELETE_TABLE,
                    payload={'n': event_publisher.get_hash(table_name)}
                )
                self.delete_all_event_source_mappings(table_arn)
                dynamodbstreams_api.delete_streams(table_arn)
                TABLE_TAGS.pop(table_arn, None)
            return

        elif action == 'UpdateTable':
            if 'StreamSpecification' in data:
                if response.status_code == 200:
                    content = json.loads(to_str(response._content))
                    create_dynamodb_stream(data, content['TableDescription'].get('LatestStreamLabel'))
            return

        elif action == 'TagResource':
            table_arn = data['ResourceArn']
            if table_arn not in TABLE_TAGS:
                TABLE_TAGS[table_arn] = {}
            TABLE_TAGS[table_arn].update({tag['Key']: tag['Value'] for tag in data.get('Tags', [])})
            return

        elif action == 'UntagResource':
            table_arn = data['ResourceArn']
            for tag_key in data.get('TagKeys', []):
                TABLE_TAGS.get(table_arn, {}).pop(tag_key, None)
            return

        else:
            # nothing to do
            return

        if event_sources_or_streams_enabled and records and 'eventName' in records[0]:
            if 'TableName' in data:
                records[0]['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
            forward_to_lambda(records)
            records = self.prepare_records_to_forward_to_ddb_stream(records)
            forward_to_ddb_stream(records)

    # -------------
    # UTIL METHODS
    # -------------

    def prepare_request_headers(self, headers):
        # Note: We need to ensure that the same access key is used here for all requests,
        # otherwise DynamoDBLocal stores tables/items in separate namespaces
        headers['Authorization'] = re.sub(r'Credential=[^/]+/',
            r'Credential=%s/' % constants.TEST_AWS_ACCESS_KEY_ID, headers.get('Authorization') or '')

    def prepare_batch_write_item_records(self, record, data):
        records = []
        unprocessed_items = []
        i = 0
        for table_name in sorted(data['RequestItems'].keys()):
            for request in data['RequestItems'][table_name]:
                put_request = request.get('PutRequest')

                if put_request:
                    if len(self._thread_local('existing_items')) > i:
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
                    if len(self._thread_local('unprocessed_items')) > i:
                        unprocessed_item = self._thread_local('unprocessed_items')[i]
                        if unprocessed_item:
                            unprocessed_item = json.loads(json.dumps({'PutRequest': unprocessed_item}))
                            unprocessed_items.append(unprocessed_item)

                delete_request = request.get('DeleteRequest')
                if delete_request:
                    if len(self._thread_local('existing_items')) > i:
                        keys = delete_request['Key']
                        if isinstance(keys, Response):
                            return keys
                        new_record = clone(record)
                        new_record['eventName'] = 'REMOVE'
                        new_record['dynamodb']['Keys'] = keys
                        new_record['dynamodb']['OldImage'] = self._thread_local('existing_items')[i]
                        new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                        records.append(new_record)
                    if len(self._thread_local('unprocessed_items')) > i:
                        unprocessed_item = self._thread_local('unprocessed_items')[i]
                        if unprocessed_item:
                            unprocessed_item = json.loads(json.dumps({'DeleteRequest': unprocessed_item}))
                            unprocessed_items.append(unprocessed_item)
                i += 1
        return records, unprocessed_items

    def prepare_transact_write_item_records(self, record, data):
        records = []
        # Fix issue #2745: existing_items only contain the Put/Update/Delete records,
        # so we will increase the index based on these events
        i = 0
        for request in data['TransactItems']:
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
                i += 1
            update_request = request.get('Update')
            if update_request:
                table_name = update_request['TableName']
                keys = update_request['Key']
                if isinstance(keys, Response):
                    return keys
                updated_item = find_existing_item(update_request, table_name)
                if not updated_item:
                    return []
                new_record = clone(record)
                new_record['eventName'] = 'MODIFY'
                new_record['dynamodb']['Keys'] = keys
                new_record['dynamodb']['OldImage'] = self._thread_local('existing_items')[i]
                new_record['dynamodb']['NewImage'] = updated_item
                new_record['eventSourceARN'] = aws_stack.dynamodb_table_arn(table_name)
                records.append(new_record)
                i += 1
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
                i += 1
        return records

    def prepare_records_to_forward_to_ddb_stream(self, records):
        # StreamViewType determines what information is written to the stream for the table
        # When an item in the table is modified
        for record in records:
            if record['eventName'] == 'MODIFY':
                # KEYS_ONLY  - Only the key attributes of the modified item are written to the stream
                if record['dynamodb']['StreamViewType'] == 'KEYS_ONLY':
                    del record['dynamodb']['OldImage']
                    del record['dynamodb']['NewImage']
                # NEW_IMAGE - The entire item, as it appears after it was modified, is written to the stream
                elif record['dynamodb']['StreamViewType'] == 'NEW_IMAGE':
                    del record['dynamodb']['OldImage']
                    del record['dynamodb']['Keys']
                # OLD_IMAGE - The entire item, as it appeared before it was modified, is written to the stream
                elif record['dynamodb']['StreamViewType'] == 'OLD_IMAGE':
                    del record['dynamodb']['NewImage']
                    del record['dynamodb']['Keys']
                # NEW_AND_OLD_IMAGES - Both the new and the old item images of the item are
                # written to the stream.
                elif record['dynamodb']['StreamViewType'] == 'NEW_AND_OLD_IMAGES':
                    del record['dynamodb']['Keys']
        return records

    def delete_all_event_source_mappings(self, table_arn):
        if table_arn:
            # fix start dynamodb service without lambda
            if not is_api_enabled('lambda'):
                return

            lambda_client = aws_stack.connect_to_service('lambda')
            result = lambda_client.list_event_source_mappings(EventSourceArn=table_arn)
            for event in result['EventSourceMappings']:
                event_source_mapping_id = event['UUID']
                lambda_client.delete_event_source_mapping(UUID=event_source_mapping_id)

    @staticmethod
    def _thread_local(name, default=None):
        try:
            return getattr(ProxyListenerDynamoDB.thread_local, name)
        except AttributeError:
            return default


def handle_special_request(method, path, data, headers):
    if path.startswith('/shell') or method == 'GET':
        if path == '/shell':
            headers = {'Refresh': '0; url=%s/shell/' % config.TEST_DYNAMODB_URL}
            return aws_responses.requests_response('', headers=headers)
        return True

    if method == 'OPTIONS':
        return 200


def create_global_table(data):
    table_name = data['GlobalTableName']
    if table_name in GLOBAL_TABLES:
        return get_error_message('Global Table with this name already exists', 'GlobalTableAlreadyExistsException')
    GLOBAL_TABLES[table_name] = data
    for group in data.get('ReplicationGroup', []):
        group['ReplicaStatus'] = 'ACTIVE'
        group['ReplicaStatusDescription'] = 'Replica active'
    result = {'GlobalTableDescription': data}
    return result


def describe_global_table(data):
    table_name = data['GlobalTableName']
    details = GLOBAL_TABLES.get(table_name)
    if not details:
        return get_error_message('Global Table with this name does not exist', 'GlobalTableNotFoundException')
    result = {'GlobalTableDescription': details}
    return result


def list_global_tables(data):
    result = [select_attributes(tab, ['GlobalTableName', 'ReplicationGroup']) for tab in GLOBAL_TABLES.values()]
    result = {'GlobalTables': result}
    return result


def update_global_table(data):
    table_name = data['GlobalTableName']
    details = GLOBAL_TABLES.get(table_name)
    if not details:
        return get_error_message('Global Table with this name does not exist', 'GlobalTableNotFoundException')
    for update in data.get('ReplicaUpdates', []):
        repl_group = details['ReplicationGroup']
        # delete existing
        delete = update.get('Delete')
        if delete:
            details['ReplicationGroup'] = [g for g in repl_group if g['RegionName'] != delete['RegionName']]
        # create new
        create = update.get('Create')
        if create:
            exists = [g for g in repl_group if g['RegionName'] == create['RegionName']]
            if exists:
                continue
            new_group = {
                'RegionName': create['RegionName'], 'ReplicaStatus': 'ACTIVE',
                'ReplicaStatusDescription': 'Replica active'
            }
            details['ReplicationGroup'].append(new_group)
    result = {'GlobalTableDescription': details}
    return result


def is_index_query_valid(table_name, index_query_type):
    schema = get_table_schema(table_name)
    for index in schema['Table'].get('GlobalSecondaryIndexes', []):
        index_projection_type = index.get('Projection').get('ProjectionType')
        if index_query_type == 'ALL_ATTRIBUTES' and index_projection_type != 'ALL':
            return False
    return True


def has_event_sources_or_streams_enabled(table_name, cache={}):
    if not table_name:
        return
    table_arn = aws_stack.dynamodb_table_arn(table_name)
    cached = cache.get(table_arn)
    if isinstance(cached, bool):
        return cached
    sources = lambda_api.get_event_sources(source_arn=table_arn)
    result = False
    if sources:
        result = True
    if not result and dynamodbstreams_api.get_stream_for_table(table_arn):
        result = True
    cache[table_arn] = result
    return result


def get_table_schema(table_name):
    key = '%s/%s' % (aws_stack.get_region(), table_name)
    schema = SCHEMA_CACHE.get(key)
    if not schema:
        ddb_client = aws_stack.connect_to_service('dynamodb')
        schema = ddb_client.describe_table(TableName=table_name)
        SCHEMA_CACHE[key] = schema
    return schema


def find_existing_item(put_item, table_name=None):
    table_name = table_name or put_item['TableName']
    ddb_client = aws_stack.connect_to_service('dynamodb')

    search_key = {}
    if 'Key' in put_item:
        search_key = put_item['Key']
    else:
        schema = get_table_schema(table_name)
        schemas = [schema['Table']['KeySchema']]
        for index in schema['Table'].get('GlobalSecondaryIndexes', []):
            # TODO
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
    if not existing_item:
        return existing_item
    if 'Item' not in existing_item:
        if 'message' in existing_item:
            table_names = ddb_client.list_tables()['TableNames']
            msg = ('Unable to get item from DynamoDB (existing tables: %s ...truncated if >100 tables): %s' %
                (table_names, existing_item['message']))
            LOGGER.warning(msg)
        return
    return existing_item.get('Item')


def get_error_message(message, error_type):
    response = error_response(message=message, error_type=error_type)
    fix_headers_for_updated_response(response)
    return response


def get_table_not_found_error():
    return get_error_message(message='Cannot do operations on a non-existent table',
                             error_type='ResourceNotFoundException')


def fix_headers_for_updated_response(response):
    response.headers['Content-Length'] = len(to_bytes(response.content))
    response.headers['x-amz-crc32'] = calculate_crc32(response)


def update_put_item_response_content(data, response_content):
    # when return-values variable is set only then attribute data should be returned
    # in the response otherwise by default is should not return any data.
    # https://github.com/localstack/localstack/issues/2121
    if data.get('ReturnValues'):
        response_content = json.dumps({'Attributes': data['Item']})
    return response_content


def calculate_crc32(response):
    return crc32(to_bytes(response.content)) & 0xffffffff


def create_dynamodb_stream(data, latest_stream_label):
    stream = data['StreamSpecification']
    enabled = stream.get('StreamEnabled')

    if enabled not in [False, 'False']:
        table_name = data['TableName']
        view_type = stream['StreamViewType']

        dynamodbstreams_api.add_dynamodb_stream(
            table_name=table_name,
            latest_stream_label=latest_stream_label,
            view_type=view_type,
            enabled=enabled
        )


def forward_to_lambda(records):
    for record in records:
        sources = lambda_api.get_event_sources(source_arn=record['eventSourceARN'])
        event = {
            'Records': [record]
        }
        for src in sources:
            if src.get('State') != 'Enabled':
                continue
            lambda_api.run_lambda(func_arn=src['FunctionArn'], event=event, context={},
                asynchronous=not config.SYNCHRONOUS_DYNAMODB_EVENTS)


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
            return error_response(
                error_type='ValidationException',
                message='One of the required keys was not given a value'
            )

        result[attr_name] = item[attr_name]

    return result


def dynamodb_get_table_stream_specification(table_name):
    try:
        return get_table_schema(table_name)['Table'].get('StreamSpecification')
    except Exception as e:
        LOGGER.info('Unable to get stream specification for table %s : %s %s' % (table_name, e,
            traceback.format_exc()))
        raise e


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


# instantiate listener
UPDATE_DYNAMODB = ProxyListenerDynamoDB()
