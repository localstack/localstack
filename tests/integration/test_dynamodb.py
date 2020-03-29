# -*- coding: utf-8 -*-

import unittest
import json
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import json_safe, short_uid

PARTITION_KEY = 'id'

TEST_DDB_TABLE_NAME = 'test-ddb-table-1'
TEST_DDB_TABLE_NAME_2 = 'test-ddb-table-2'
TEST_DDB_TABLE_NAME_3 = 'test-ddb-table-3'
TEST_DDB_TABLE_NAME_4 = 'test-ddb-table-4'

TEST_DDB_TAGS = [
    {
        'Key': 'Name',
        'Value': 'test-table'
    },
    {
        'Key': 'TestKey',
        'Value': 'true'
    }
]


class DynamoDBIntegrationTest (unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dynamodb = aws_stack.connect_to_resource('dynamodb')

    def test_non_ascii_chars(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

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
            self.assertEqual(item1, item2)

        # clean up
        delete_table(TEST_DDB_TABLE_NAME)

    def test_large_data_download(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_2)

        # Create a large amount of items
        num_items = 20
        for i in range(0, num_items):
            item = {PARTITION_KEY: 'id%s' % i, 'data1': 'foobar123 ' * 1000}
            table.put_item(Item=item)

        # Retrieve the items. The data will be transmitted to the client with chunked transfer encoding
        result = table.scan(TableName=TEST_DDB_TABLE_NAME_2)
        self.assertEqual(len(result['Items']), num_items)

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_2)

    def test_time_to_live(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_3, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_3)

        # Insert some items to the table
        items = {
            'id1': {PARTITION_KEY: 'id1', 'data': 'IT IS'},
            'id2': {PARTITION_KEY: 'id2', 'data': 'TIME'},
            'id3': {PARTITION_KEY: 'id3', 'data': 'TO LIVE!'}
        }
        for k, item in items.items():
            table.put_item(Item=item)

        # Describe TTL when still unset.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'], 'DISABLED')

        # Enable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response._content)['TimeToLiveSpecification']['Enabled'])

        # Describe TTL status after being enabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'], 'ENABLED')

        # Disable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, False)
        self.assertEqual(response.status_code, 200)
        self.assertFalse(json.loads(response._content)['TimeToLiveSpecification']['Enabled'])

        # Describe TTL status after being disabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'], 'DISABLED')

        # Enable TTL for given table again
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(json.loads(response._content)['TimeToLiveSpecification']['Enabled'])

        # Describe TTL status after being enabled again.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'], 'ENABLED')

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_3)

    def test_list_tags_of_resource(self):
        table_name = 'ddb-table-%s' % short_uid()
        dynamodb = aws_stack.connect_to_service('dynamodb')

        rs = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{
                'AttributeName': 'id', 'KeyType': 'HASH'
            }],
            AttributeDefinitions=[{
                'AttributeName': 'id', 'AttributeType': 'S'
            }],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5
            },
            Tags=TEST_DDB_TAGS
        )
        table_arn = rs['TableDescription']['TableArn']

        rs = dynamodb.list_tags_of_resource(
            ResourceArn=table_arn
        )

        self.assertEqual(rs['Tags'], TEST_DDB_TAGS)

        dynamodb.tag_resource(
            ResourceArn=table_arn,
            Tags=[
                {
                    'Key': 'NewKey',
                    'Value': 'TestValue'
                }
            ]
        )

        rs = dynamodb.list_tags_of_resource(
            ResourceArn=table_arn
        )

        self.assertEqual(len(rs['Tags']), len(TEST_DDB_TAGS) + 1)

        tags = {tag['Key']: tag['Value'] for tag in rs['Tags']}
        self.assertIn('NewKey', tags.keys())
        self.assertEqual(tags['NewKey'], 'TestValue')

        dynamodb.untag_resource(
            ResourceArn=table_arn,
            TagKeys=[
                'Name', 'NewKey'
            ]
        )

        rs = dynamodb.list_tags_of_resource(
            ResourceArn=table_arn
        )
        tags = {tag['Key']: tag['Value'] for tag in rs['Tags']}
        self.assertNotIn('Name', tags.keys())
        self.assertNotIn('NewKey', tags.keys())

        delete_table(table_name)

    def test_region_replacement(self):
        aws_stack.create_dynamodb_table(
            TEST_DDB_TABLE_NAME_4,
            partition_key=PARTITION_KEY,
            stream_view_type='NEW_AND_OLD_IMAGES'
        )

        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_4)

        expected_arn_prefix = 'arn:aws:dynamodb:' + aws_stack.get_local_region()

        self.assertTrue(table.table_arn.startswith(expected_arn_prefix))
        self.assertTrue(table.latest_stream_arn.startswith(expected_arn_prefix))

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_4)


def delete_table(name):
    dynamodb_client = aws_stack.connect_to_service('dynamodb')
    dynamodb_client.delete_table(TableName=name)
