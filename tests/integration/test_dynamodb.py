# -*- coding: utf-8 -*-

import unittest
import json

from localstack.services.dynamodbstreams.dynamodbstreams_api import get_kinesis_stream_name
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_models import KinesisStream
from localstack.utils.aws.aws_stack import get_environment
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

    def test_stream_spec_and_region_replacement(self):
        aws_stack.create_dynamodb_table(
            TEST_DDB_TABLE_NAME_4,
            partition_key=PARTITION_KEY,
            stream_view_type='NEW_AND_OLD_IMAGES'
        )

        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME_4)

        # assert ARN formats
        expected_arn_prefix = 'arn:aws:dynamodb:' + aws_stack.get_local_region()
        self.assertTrue(table.table_arn.startswith(expected_arn_prefix))
        self.assertTrue(table.latest_stream_arn.startswith(expected_arn_prefix))

        # assert shard ID formats
        ddbstreams = aws_stack.connect_to_service('dynamodbstreams')
        result = ddbstreams.describe_stream(StreamArn=table.latest_stream_arn)['StreamDescription']
        self.assertIn('Shards', result)
        for shard in result['Shards']:
            self.assertRegex(shard['ShardId'], r'^shardId\-[0-9]{20}\-[a-zA-Z0-9]{1,36}$')

        # clean up
        delete_table(TEST_DDB_TABLE_NAME_4)

    def test_multiple_update_expressions(self):
        dynamodb = aws_stack.connect_to_service('dynamodb')
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        item_id = short_uid()
        table.put_item(Item={PARTITION_KEY: item_id, 'data': 'foobar123 ✓'})
        response = dynamodb.update_item(TableName=TEST_DDB_TABLE_NAME,
            Key={PARTITION_KEY: {'S': item_id}},
            UpdateExpression='SET attr1 = :v1, attr2 = :v2',
            ExpressionAttributeValues={
                ':v1': {'S': 'value1'},
                ':v2': {'S': 'value2'}
            })
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        item = table.get_item(Key={PARTITION_KEY: item_id})['Item']
        self.assertEqual(item['attr1'], 'value1')
        self.assertEqual(item['attr2'], 'value2')

    def test_return_values_in_put_item(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: 'id1', 'data': 'foobar'}
        item2 = {PARTITION_KEY: 'id2', 'data': 'foobar'}

        response = table.put_item(Item=item1, ReturnValues='ALL_OLD')
        # there is no data present in the table already so even if return values
        # is set to 'ALL_OLD' as there is no data it will not return any data.
        self.assertFalse(response.get('Attributes'))
        # now the same data is present so when we pass return values as 'ALL_OLD'
        # it should give us attributes
        response = table.put_item(Item=item1, ReturnValues='ALL_OLD')
        self.assertTrue(response.get('Attributes'))
        self.assertEqual(response.get('Attributes').get('id'), item1.get('id'))
        self.assertEqual(response.get('Attributes').get('data'), item1.get('data'))

        response = table.put_item(Item=item2)
        # we do not have any same item as item2 already so when we add this by default
        # return values is set to None so no Attribute values should be returned
        self.assertFalse(response.get('Attributes'))

        response = table.put_item(Item=item2)
        # in this case we already have item2 in the table so on this request
        # it should not return any data as return values is set to None so no
        # Attribute values should be returned
        self.assertFalse(response.get('Attributes'))

    def test_empty_and_binary_values(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        table = self.dynamodb.Table(TEST_DDB_TABLE_NAME)

        # items which are being used to put in the table
        item1 = {PARTITION_KEY: 'id1', 'data': ''}
        item2 = {PARTITION_KEY: 'id2', 'data': b'foobar'}

        response = table.put_item(Item=item1)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        response = table.put_item(Item=item2)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_dynamodb_stream_shard_iterator(self):
        def wait_for_stream_created(table_name):
            stream_name = get_kinesis_stream_name(table_name)
            stream = KinesisStream(id=stream_name, num_shards=1)
            kinesis = aws_stack.connect_to_service('kinesis', env=get_environment(None))
            stream.connect(kinesis)
            stream.wait_for()

        dynamodb = aws_stack.connect_to_service('dynamodb')
        ddbstreams = aws_stack.connect_to_service('dynamodbstreams')

        table_name = 'table_with_stream'
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
            StreamSpecification={
                'StreamEnabled': True,
                'StreamViewType': 'NEW_IMAGE',
            },
            ProvisionedThroughput={
                'ReadCapacityUnits': 5, 'WriteCapacityUnits': 5
            },
        )

        wait_for_stream_created(table_name)

        stream_arn = table['TableDescription']['LatestStreamArn']
        result = ddbstreams.describe_stream(StreamArn=stream_arn)

        response = ddbstreams.get_shard_iterator(StreamArn=stream_arn,
                                                 ShardId=result['StreamDescription']['Shards'][0]['ShardId'],
                                                 ShardIteratorType='LATEST'
                                                 )
        self.assertIn('ShardIterator', response)

    def test_global_tables(self):
        aws_stack.create_dynamodb_table(TEST_DDB_TABLE_NAME, partition_key=PARTITION_KEY)
        dynamodb = aws_stack.connect_to_service('dynamodb')

        # create global table
        regions = [{'RegionName': 'us-east-1'}, {'RegionName': 'us-west-1'}, {'RegionName': 'eu-central-1'}]
        response = dynamodb.create_global_table(GlobalTableName=TEST_DDB_TABLE_NAME,
            ReplicationGroup=regions)['GlobalTableDescription']
        self.assertIn('ReplicationGroup', response)
        self.assertEqual(len(regions), len(response['ReplicationGroup']))

        # describe global table
        response = dynamodb.describe_global_table(GlobalTableName=TEST_DDB_TABLE_NAME)['GlobalTableDescription']
        self.assertIn('ReplicationGroup', response)
        self.assertEqual(len(regions), len(response['ReplicationGroup']))

        # update global table
        updates = [
            {'Create': {'RegionName': 'us-east-2'}},
            {'Create': {'RegionName': 'us-west-2'}},
            {'Delete': {'RegionName': 'us-west-1'}}
        ]
        response = dynamodb.update_global_table(GlobalTableName=TEST_DDB_TABLE_NAME,
            ReplicaUpdates=updates)['GlobalTableDescription']
        self.assertIn('ReplicationGroup', response)
        self.assertEqual(len(regions) + 1, len(response['ReplicationGroup']))

        # assert exceptions for invalid requests
        with self.assertRaises(Exception) as ctx:
            dynamodb.create_global_table(GlobalTableName=TEST_DDB_TABLE_NAME, ReplicationGroup=regions)
        self.assertIn('GlobalTableAlreadyExistsException', str(ctx.exception))
        with self.assertRaises(Exception) as ctx:
            dynamodb.describe_global_table(GlobalTableName='invalid-table-name')
        self.assertIn('GlobalTableNotFoundException', str(ctx.exception))

    def test_create_duplicate_table(self):
        table_name = 'duplicateTable'
        dynamodb = aws_stack.connect_to_service('dynamodb')

        dynamodb.create_table(
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

        with self.assertRaises(Exception) as ctx:
            dynamodb.create_table(
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
        self.assertIn('ResourceInUseException', str(ctx.exception))


def delete_table(name):
    dynamodb_client = aws_stack.connect_to_service('dynamodb')
    dynamodb_client.delete_table(TableName=name)
