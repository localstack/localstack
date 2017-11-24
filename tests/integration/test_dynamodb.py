# -*- coding: utf-8 -*-

import unittest
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import json_safe

TEST_DDB_TABLE_NAME = 'test-ddb-table-1'
TEST_DDB_TABLE_NAME_2 = 'test-ddb-table-2'
PARTITION_KEY = 'id'


class DynamoDBIntegrationTest (unittest.TestCase):

    def test_non_ascii_chars(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')

        testutil.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME)

        # write some items containing non-ASCII characters
        items = {
            'id1': {PARTITION_KEY: 'id1', 'data': 'foobar123 ✓'},
            'id2': {PARTITION_KEY: 'id2', 'data': 'foobar123 £'},
            'id3': {PARTITION_KEY: 'id3', 'data': 'foobar123 ¢'}
        }
        for k, item in items.items():
            table.put_item(Item=item)

        for item_id in items.keys():
            item = table.get_item(Key={PARTITION_KEY: item_id})['Item']
            # need to fix up the JSON and convert str to unicode for Python 2
            item1 = json_safe(item)
            item2 = json_safe(items[item_id])
            assert item1 == item2

    def test_large_data_download(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')
        dynamodb_client = aws_stack.connect_to_service('dynamodb')

        testutil.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME_2)

        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: 'id%s' % i, 'data1': 'foobar123 ' * 1000}
            table.put_item(Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = table.scan(TableName=TEST_DDB_TABLE_NAME_2)
        assert len(result['Items']) == num_items

        # Clean up
        dynamodb_client.delete_table(TableName=TEST_DDB_TABLE_NAME_2)
