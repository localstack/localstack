# -*- coding: utf-8 -*-

import unittest
import json
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import json_safe

TEST_DDB_TABLE_NAME = 'test-ddb-table-1'
TEST_DDB_TABLE_NAME_2 = 'test-ddb-table-2'
TEST_DDB_TABLE_NAME_3 = 'test-ddb-table-3'
TEST_DDB_TABLE_NAME_4 = 'test-ddb-table-4'
PARTITION_KEY = ['id']


class DynamoDBIntegrationTest (unittest.TestCase):

    def test_non_ascii_chars(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')

        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
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

        # clean up
        delete_table(TEST_DDB_TABLE_NAME)

    def test_large_data_download(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')
        dynamodb_client = aws_stack.connect_to_service('dynamodb')

        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_2, partition_key=PARTITION_KEY)
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

    def test_time_to_live(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')
        dynamodb_client = aws_stack.connect_to_service('dynamodb')

        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME_3, partition_key=PARTITION_KEY)
        table = dynamodb.Table(TEST_DDB_TABLE_NAME_3)

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
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'] == 'DISABLED'

        # Enable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveSpecification']['Enabled'] is True

        # Describe TTL status after being enabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'] == 'ENABLED'

        # Disable TTL for given table
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, False)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveSpecification']['Enabled'] is False

        # Describe TTL status after being disabled.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'] == 'DISABLED'

        # Enable TTL for given table again
        response = testutil.send_update_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3, True)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveSpecification']['Enabled'] is True

        # Describe TTL status after being enabled again.
        response = testutil.send_describe_dynamodb_ttl_request(TEST_DDB_TABLE_NAME_3)
        assert response.status_code == 200
        assert json.loads(response._content)['TimeToLiveDescription']['TimeToLiveStatus'] == 'ENABLED'

        # Clean up table
        dynamodb_client.delete_table(TableName=TEST_DDB_TABLE_NAME_3)

    def test_tag_resource(self):
        response = testutil.send_dynamodb_request('', action='TagResource', request_body=json.dumps({
            'ResourceArn': testutil.get_sample_arn('dynamodb', 'table'),
            'Tags': [{'tagkey1': 'tagvalue1'}, {'tagkey2': 'tagvalue2'}, {'tagkey3': 'tagvalue3'}]
        }))
        assert response.status_code == 200
        assert not response._content  # Empty string if tagging succeeded (mocked for now)

    def test_untag_resource(self):
        response = testutil.send_dynamodb_request('', action='UntagResource', request_body=json.dumps({
            'ResourceArn': testutil.get_sample_arn('dynamodb', 'table'),
            'TagKeys': ['tagkey1', 'tagkey2']  # Keys to untag
        }))
        assert response.status_code == 200
        assert not response._content  # Empty string if untagging succeeded (mocked for now)

    def test_list_tags_of_resource(self):
        response = testutil.send_dynamodb_request('', action='ListTagsOfResource', request_body=json.dumps({
            'ResourceArn': testutil.get_sample_arn('dynamodb', 'table')
        }))
        assert response.status_code == 200
        assert json.loads(response._content)['Tags'] == []  # Empty list returned

    def test_region_replacement(self):
        dynamodb = aws_stack.connect_to_resource('dynamodb')
        aws_stack.create_dynamodb_table(
            TEST_DDB_TABLE_NAME_4,
            partition_key=PARTITION_KEY,
            stream_view_type='NEW_AND_OLD_IMAGES'
        )

        table = dynamodb.Table(TEST_DDB_TABLE_NAME_4)

        expected_arn_prefix = 'arn:aws:dynamodb:' + aws_stack.get_local_region()

        assert table.table_arn.startswith(expected_arn_prefix)
        assert table.latest_stream_arn.startswith(expected_arn_prefix)

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_4)


def delete_table(name):
    dynamodb_client = aws_stack.connect_to_service('dynamodb')
    dynamodb_client.delete_table(TableName=name)
