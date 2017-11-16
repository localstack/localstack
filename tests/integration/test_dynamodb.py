# -*- coding: utf-8 -*-

import unittest
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import json_safe

TEST_DDB_TABLE_NAME = 'test-ddb-table-1'
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
