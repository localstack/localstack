# -*- coding: utf-8 -*-

import json
import time
import base64
import logging
import unittest
from datetime import datetime, timedelta
import pytest
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import (
    load_file, save_file, short_uid, clone, to_bytes, to_str, run_safe, retry, new_tmp_file)
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.testutil import get_lambda_log_events
from .lambdas import lambda_integration
from .test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_PYTHON_ECHO, TEST_LAMBDA_LIBS, LambdaTestBase

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_LAMBDA_SOURCE_STREAM_NAME = 'test_source_stream'
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME_DDB = 'test_lambda_ddb'
TEST_LAMBDA_NAME_QUEUE = 'test_lambda_queue'
TEST_FIREHOSE_NAME = 'test_firehose'
TEST_BUCKET_NAME = lambda_integration.TEST_BUCKET_NAME
TEST_TOPIC_NAME = 'test_topic'
TEST_TAGS = [{'Key': 'MyTag', 'Value': 'Value'}]
# constants for forward chain K1->L1->K2->L2
TEST_CHAIN_STREAM1_NAME = 'test_chain_stream_1'
TEST_CHAIN_STREAM2_NAME = 'test_chain_stream_2'
TEST_CHAIN_LAMBDA1_NAME = 'test_chain_lambda_1'
TEST_CHAIN_LAMBDA2_NAME = 'test_chain_lambda_2'

PARTITION_KEY = 'id'

# set up logger
LOGGER = logging.getLogger(__name__)

TEST_HANDLER = """
def handler(event, *args):
    return {}
"""


class IntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Note: create scheduled Lambda here - assertions will be run in test_scheduled_lambda() below..

        # create test Lambda
        cls.scheduled_lambda_name = 'scheduled-%s' % short_uid()
        handler_file = new_tmp_file()
        save_file(handler_file, TEST_HANDLER)
        resp = testutil.create_lambda_function(handler_file=handler_file, func_name=cls.scheduled_lambda_name)
        func_arn = resp['CreateFunctionResponse']['FunctionArn']

        # create scheduled Lambda function
        rule_name = 'rule-%s' % short_uid()
        events = aws_stack.connect_to_service('events')
        events.put_rule(Name=rule_name, ScheduleExpression='rate(1 minutes)')
        events.put_targets(Rule=rule_name, Targets=[{'Id': 'target-%s' % short_uid(), 'Arn': func_arn}])

    @classmethod
    def tearDownClass(cls):
        testutil.delete_lambda_function(cls.scheduled_lambda_name)

    def test_firehose_s3(self):
        s3_resource = aws_stack.connect_to_resource('s3')
        firehose = aws_stack.connect_to_service('firehose')

        s3_prefix = '/testdata'
        test_data = '{"test": "firehose_data_%s"}' % short_uid()
        # create Firehose stream
        stream = firehose.create_delivery_stream(
            DeliveryStreamName=TEST_FIREHOSE_NAME,
            S3DestinationConfiguration={
                'RoleARN': aws_stack.iam_resource_arn('firehose'),
                'BucketARN': aws_stack.s3_bucket_arn(TEST_BUCKET_NAME),
                'Prefix': s3_prefix
            },
            Tags=TEST_TAGS
        )
        self.assertTrue(stream)
        self.assertIn(TEST_FIREHOSE_NAME, firehose.list_delivery_streams()['DeliveryStreamNames'])
        tags = firehose.list_tags_for_delivery_stream(DeliveryStreamName=TEST_FIREHOSE_NAME)
        self.assertEqual(TEST_TAGS, tags['Tags'])
        # create target S3 bucket
        s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME)

        # put records
        firehose.put_record(
            DeliveryStreamName=TEST_FIREHOSE_NAME,
            Record={
                'Data': to_bytes(test_data)
            }
        )
        # check records in target bucket
        all_objects = testutil.list_all_s3_objects()
        testutil.assert_objects(json.loads(to_str(test_data)), all_objects)
        # check file layout in target bucket
        all_objects = testutil.map_all_s3_objects(buckets=[TEST_BUCKET_NAME])
        for key in all_objects.keys():
            self.assertRegexpMatches(key, r'.*/\d{4}/\d{2}/\d{2}/\d{2}/.*\-\d{4}\-\d{2}\-\d{2}\-\d{2}.*')

    def test_firehose_kinesis_to_s3(self):
        kinesis = aws_stack.connect_to_service('kinesis')
        s3_resource = aws_stack.connect_to_resource('s3')
        firehose = aws_stack.connect_to_service('firehose')

        aws_stack.create_kinesis_stream(TEST_STREAM_NAME, delete=True)

        s3_prefix = '/testdata'
        test_data = '{"test": "firehose_data_%s"}' % short_uid()

        # create Firehose stream
        stream = firehose.create_delivery_stream(
            DeliveryStreamType='KinesisStreamAsSource',
            KinesisStreamSourceConfiguration={
                'RoleARN': aws_stack.iam_resource_arn('firehose'),
                'KinesisStreamARN': aws_stack.kinesis_stream_arn(TEST_STREAM_NAME)
            },
            DeliveryStreamName=TEST_FIREHOSE_NAME,
            S3DestinationConfiguration={
                'RoleARN': aws_stack.iam_resource_arn('firehose'),
                'BucketARN': aws_stack.s3_bucket_arn(TEST_BUCKET_NAME),
                'Prefix': s3_prefix
            }
        )
        self.assertTrue(stream)
        self.assertIn(TEST_FIREHOSE_NAME, firehose.list_delivery_streams()['DeliveryStreamNames'])

        # create target S3 bucket
        s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME)

        # put records
        kinesis.put_record(
            Data=to_bytes(test_data),
            PartitionKey='testId',
            StreamName=TEST_STREAM_NAME
        )

        time.sleep(3)

        # check records in target bucket
        all_objects = testutil.list_all_s3_objects()
        testutil.assert_objects(json.loads(to_str(test_data)), all_objects)

    # TODO fix duplication with test_lambda_streams_batch_and_transactions(..)!
    # @profiled()
    def test_kinesis_lambda_sns_ddb_sqs_streams(self):
        def create_kinesis_stream(name, delete=False):
            stream = aws_stack.create_kinesis_stream(name, delete=delete)
            stream.wait_for()

        ddb_lease_table_suffix = '-kclapp'
        table_name = TEST_TABLE_NAME + 'klsdss' + ddb_lease_table_suffix
        stream_name = TEST_STREAM_NAME
        lambda_stream_name = 'lambda-stream-%s' % short_uid()
        dynamodb = aws_stack.connect_to_resource('dynamodb')
        dynamodb_service = aws_stack.connect_to_service('dynamodb')
        dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams')
        kinesis = aws_stack.connect_to_service('kinesis')
        sns = aws_stack.connect_to_service('sns')
        sqs = aws_stack.connect_to_service('sqs')

        LOGGER.info('Creating test streams...')
        run_safe(lambda: dynamodb_service.delete_table(
            TableName=stream_name + ddb_lease_table_suffix), print_error=False)

        create_kinesis_stream(stream_name, delete=True)
        create_kinesis_stream(TEST_LAMBDA_SOURCE_STREAM_NAME)

        events = []

        # subscribe to inbound Kinesis stream
        def process_records(records, shard_id):
            events.extend(records)

        # start the KCL client process in the background
        kinesis_connector.listen_to_kinesis(stream_name, listener_func=process_records,
            wait_until_started=True, ddb_lease_table_suffix=ddb_lease_table_suffix)

        LOGGER.info('Kinesis consumer initialized.')

        # create table with stream forwarding config
        aws_stack.create_dynamodb_table(table_name, partition_key=PARTITION_KEY,
            stream_view_type='NEW_AND_OLD_IMAGES')

        # list DDB streams and make sure the table stream is there
        streams = dynamodbstreams.list_streams()
        ddb_event_source_arn = None
        for stream in streams['Streams']:
            if stream['TableName'] == table_name:
                ddb_event_source_arn = stream['StreamArn']
        self.assertTrue(ddb_event_source_arn)

        # deploy test lambda connected to DynamoDB Stream
        zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
            libs=TEST_LAMBDA_LIBS)
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_DDB,
            zip_file=zip_file, event_source_arn=ddb_event_source_arn, delete=True)
        # make sure we cannot create Lambda with same name twice
        with pytest.raises(Exception):
            testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_DDB,
                                            zip_file=zip_file, event_source_arn=ddb_event_source_arn)

        # deploy test lambda connected to Kinesis Stream
        kinesis_event_source_arn = kinesis.describe_stream(
            StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)['StreamDescription']['StreamARN']
        testutil.create_lambda_function(func_name=lambda_stream_name,
            zip_file=zip_file, event_source_arn=kinesis_event_source_arn)

        # deploy test lambda connected to SQS queue
        sqs_queue_info = testutil.create_sqs_queue(TEST_LAMBDA_NAME_QUEUE)
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_QUEUE,
            zip_file=zip_file, event_source_arn=sqs_queue_info['QueueArn'])

        # set number of items to update/put to table
        num_events_ddb = 15
        num_put_new_items = 5
        num_put_existing_items = 2
        num_batch_items = 3
        num_updates_ddb = num_events_ddb - num_put_new_items - num_put_existing_items - num_batch_items

        LOGGER.info('Putting %s items to table...' % num_events_ddb)
        table = dynamodb.Table(table_name)
        for i in range(0, num_put_new_items):
            table.put_item(Item={
                PARTITION_KEY: 'testId%s' % i,
                'data': 'foobar123'
            })
        # Put items with an already existing ID (fix https://github.com/localstack/localstack/issues/522)
        for i in range(0, num_put_existing_items):
            table.put_item(Item={
                PARTITION_KEY: 'testId%s' % i,
                'data': 'foobar123_put_existing'
            })

        # batch write some items containing non-ASCII characters
        dynamodb.batch_write_item(RequestItems={table_name: [
            {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123 ✓'}}},
            {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123 £'}}},
            {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123 ¢'}}}
        ]})
        # update some items, which also triggers notification events
        for i in range(0, num_updates_ddb):
            dynamodb_service.update_item(TableName=table_name,
                Key={PARTITION_KEY: {'S': 'testId%s' % i}},
                AttributeUpdates={'data': {
                    'Action': 'PUT',
                    'Value': {'S': 'foobar123_updated'}
                }})

        # put items to stream
        num_events_kinesis = 1
        num_kinesis_records = 10
        LOGGER.info('Putting %s records in %s event to stream...' % (num_kinesis_records, num_events_kinesis))
        kinesis.put_records(
            Records=[
                {
                    'Data': '{}',
                    'PartitionKey': 'testId%s' % i
                } for i in range(0, num_kinesis_records)
            ], StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME
        )

        # put 1 item to stream that will trigger an error in the Lambda
        num_events_kinesis_err = 1
        for i in range(num_events_kinesis_err):
            kinesis.put_record(Data='{"%s": 1}' % lambda_integration.MSG_BODY_RAISE_ERROR_FLAG,
                PartitionKey='testIdError', StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)

        # create SNS topic, connect it to the Lambda, publish test messages
        num_events_sns = 3
        response = sns.create_topic(Name=TEST_TOPIC_NAME)
        sns.subscribe(TopicArn=response['TopicArn'], Protocol='lambda',
            Endpoint=aws_stack.lambda_function_arn(lambda_stream_name))
        for i in range(num_events_sns):
            sns.publish(TopicArn=response['TopicArn'], Subject='test_subject', Message='test message %s' % i)

        # get latest records
        latest = aws_stack.kinesis_get_latest_records(TEST_LAMBDA_SOURCE_STREAM_NAME,
            shard_id='shardId-000000000000', count=10)
        self.assertEqual(len(latest), 10)

        # send messages to SQS queue
        num_events_sqs = 4
        for i in range(num_events_sqs):
            sqs.send_message(QueueUrl=sqs_queue_info['QueueUrl'], MessageBody=str(i))

        LOGGER.info('Waiting some time before finishing test.')
        time.sleep(2)

        num_events_lambda = num_events_ddb + num_events_sns + num_events_sqs
        num_events = num_events_lambda + num_kinesis_records

        def check_events():
            if len(events) != num_events:
                LOGGER.warning(('DynamoDB and Kinesis updates retrieved (actual/expected): %s/%s') %
                    (len(events), num_events))
            self.assertEqual(len(events), num_events)
            event_items = [json.loads(base64.b64decode(e['data'])) for e in events]
            # make sure the we have the right amount of INSERT/MODIFY event types
            inserts = [e for e in event_items if e.get('__action_type') == 'INSERT']
            modifies = [e for e in event_items if e.get('__action_type') == 'MODIFY']
            self.assertEqual(len(inserts), num_put_new_items + num_batch_items)
            self.assertEqual(len(modifies), num_put_existing_items + num_updates_ddb)

        # this can take a long time in CI, make sure we give it enough time/retries
        retry(check_events, retries=15, sleep=2)

        # check cloudwatch notifications
        def check_cw_invocations():
            num_invocations = get_lambda_invocations_count(lambda_stream_name)
            self.assertEqual(num_invocations, num_events_kinesis + num_events_kinesis_err + num_events_sns)
            num_error_invocations = get_lambda_invocations_count(lambda_stream_name, 'Errors')
            self.assertEqual(num_error_invocations, num_events_kinesis_err)

        # Lambda invocations are running asynchronously, hence sleep some time here to wait for results
        retry(check_cw_invocations, retries=5, sleep=2)

        # clean up
        testutil.delete_lambda_function(lambda_stream_name)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_DDB)
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_QUEUE)
        sqs.delete_queue(QueueUrl=sqs_queue_info['QueueUrl'])

    def test_lambda_streams_batch_and_transactions(self):
        ddb_lease_table_suffix = '-kclapp2'
        table_name = TEST_TABLE_NAME + 'lsbat' + ddb_lease_table_suffix
        stream_name = TEST_STREAM_NAME
        dynamodb = aws_stack.connect_to_service('dynamodb', client=True)
        dynamodb_service = aws_stack.connect_to_service('dynamodb')
        dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams')

        LOGGER.info('Creating test streams...')
        run_safe(lambda: dynamodb_service.delete_table(
            TableName=stream_name + ddb_lease_table_suffix), print_error=False)
        aws_stack.create_kinesis_stream(stream_name, delete=True)

        events = []

        # subscribe to inbound Kinesis stream
        def process_records(records, shard_id):
            events.extend(records)

        # start the KCL client process in the background
        kinesis_connector.listen_to_kinesis(stream_name, listener_func=process_records,
            wait_until_started=True, ddb_lease_table_suffix=ddb_lease_table_suffix)

        LOGGER.info('Kinesis consumer initialized.')

        # create table with stream forwarding config
        aws_stack.create_dynamodb_table(table_name, partition_key=PARTITION_KEY,
            stream_view_type='NEW_AND_OLD_IMAGES')

        # list DDB streams and make sure the table stream is there
        streams = dynamodbstreams.list_streams()
        ddb_event_source_arn = None
        for stream in streams['Streams']:
            if stream['TableName'] == table_name:
                ddb_event_source_arn = stream['StreamArn']
        self.assertTrue(ddb_event_source_arn)

        # deploy test lambda connected to DynamoDB Stream
        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON, libs=TEST_LAMBDA_LIBS, func_name=TEST_LAMBDA_NAME_DDB,
            event_source_arn=ddb_event_source_arn, delete=True)

        # submit a batch with writes
        dynamodb.batch_write_item(RequestItems={table_name: [
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId0'}, 'data': {'S': 'foobar123'}}}},
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId1'}, 'data': {'S': 'foobar123'}}}},
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId2'}, 'data': {'S': 'foobar123'}}}}
        ]})

        # submit a batch with writes and deletes
        dynamodb.batch_write_item(RequestItems={table_name: [
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId3'}, 'data': {'S': 'foobar123'}}}},
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId4'}, 'data': {'S': 'foobar123'}}}},
            {'PutRequest': {'Item': {PARTITION_KEY: {'S': 'testId5'}, 'data': {'S': 'foobar123'}}}},
            {'DeleteRequest': {'Key': {PARTITION_KEY: {'S': 'testId0'}}}},
            {'DeleteRequest': {'Key': {PARTITION_KEY: {'S': 'testId1'}}}},
            {'DeleteRequest': {'Key': {PARTITION_KEY: {'S': 'testId2'}}}},
        ]})

        # submit a transaction with writes and delete
        dynamodb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table_name,
                'Item': {PARTITION_KEY: {'S': 'testId6'}, 'data': {'S': 'foobar123'}}}},
            {'Put': {'TableName': table_name,
                'Item': {PARTITION_KEY: {'S': 'testId7'}, 'data': {'S': 'foobar123'}}}},
            {'Put': {'TableName': table_name,
                'Item': {PARTITION_KEY: {'S': 'testId8'}, 'data': {'S': 'foobar123'}}}},
            {'Delete': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId3'}}}},
            {'Delete': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId4'}}}},
            {'Delete': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId5'}}}},
        ])

        # submit a batch with a put over existing item
        dynamodb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table_name,
                'Item': {PARTITION_KEY: {'S': 'testId6'}, 'data': {'S': 'foobar123_updated1'}}}},
        ])

        # submit a transaction with a put over existing item
        dynamodb.transact_write_items(TransactItems=[
            {'Put': {'TableName': table_name,
                'Item': {PARTITION_KEY: {'S': 'testId7'}, 'data': {'S': 'foobar123_updated1'}}}},
        ])

        # submit a transaction with updates
        dynamodb.transact_write_items(TransactItems=[
            {'Update': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId6'}},
                'UpdateExpression': 'SET #0 = :0',
                'ExpressionAttributeNames': {'#0': 'data'},
                'ExpressionAttributeValues': {':0': {'S': 'foobar123_updated2'}}}},
            {'Update': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId7'}},
                'UpdateExpression': 'SET #0 = :0',
                'ExpressionAttributeNames': {'#0': 'data'},
                'ExpressionAttributeValues': {':0': {'S': 'foobar123_updated2'}}}},
            {'Update': {'TableName': table_name, 'Key': {PARTITION_KEY: {'S': 'testId8'}},
                'UpdateExpression': 'SET #0 = :0',
                'ExpressionAttributeNames': {'#0': 'data'},
                'ExpressionAttributeValues': {':0': {'S': 'foobar123_updated2'}}}},
        ])

        LOGGER.info('Waiting some time before finishing test.')
        time.sleep(2)

        num_insert = 9
        num_modify = 5
        num_delete = 6
        num_events = num_insert + num_modify + num_delete

        def check_events():
            if len(events) != num_events:
                LOGGER.warning(('DynamoDB updates retrieved (actual/expected): %s/%s') %
                    (len(events), num_events))
            self.assertEqual(len(events), num_events)
            event_items = [json.loads(base64.b64decode(e['data'])) for e in events]
            # make sure the we have the right amount of expected event types
            inserts = [e for e in event_items if e.get('__action_type') == 'INSERT']
            modifies = [e for e in event_items if e.get('__action_type') == 'MODIFY']
            removes = [e for e in event_items if e.get('__action_type') == 'REMOVE']
            self.assertEqual(len(inserts), num_insert)
            self.assertEqual(len(modifies), num_modify)
            self.assertEqual(len(removes), num_delete)

            # assert that all inserts were received

            for i, event in enumerate(inserts):
                self.assertNotIn('old_image', event)
                item_id = 'testId%d' % i
                matching = [i for i in inserts if i['new_image']['id'] == item_id][0]
                self.assertEqual(matching['new_image'], {'id': item_id, 'data': 'foobar123'})

            # assert that all updates were received

            def assert_updates(expected_updates, modifies):
                def found(update):
                    for modif in modifies:
                        if modif['old_image']['id'] == update['id']:
                            self.assertEqual(modif['old_image'], {'id': update['id'], 'data': update['old']})
                            self.assertEqual(modif['new_image'], {'id': update['id'], 'data': update['new']})
                            return True
                for update in expected_updates:
                    self.assertTrue(found(update))

            updates1 = [
                {'id': 'testId6', 'old': 'foobar123', 'new': 'foobar123_updated1'},
                {'id': 'testId7', 'old': 'foobar123', 'new': 'foobar123_updated1'}
            ]
            updates2 = [
                {'id': 'testId6', 'old': 'foobar123_updated1', 'new': 'foobar123_updated2'},
                {'id': 'testId7', 'old': 'foobar123_updated1', 'new': 'foobar123_updated2'},
                {'id': 'testId8', 'old': 'foobar123', 'new': 'foobar123_updated2'}
            ]

            assert_updates(updates1, modifies[:2])
            assert_updates(updates2, modifies[2:])

            # assert that all removes were received

            for i, event in enumerate(removes):
                self.assertNotIn('new_image', event)
                item_id = 'testId%d' % i
                matching = [i for i in removes if i['old_image']['id'] == item_id][0]
                self.assertEqual(matching['old_image'], {'id': item_id, 'data': 'foobar123'})

        # this can take a long time in CI, make sure we give it enough time/retries
        retry(check_events, retries=9, sleep=4)

        # clean up
        testutil.delete_lambda_function(TEST_LAMBDA_NAME_DDB)

    def test_kinesis_lambda_forward_chain(self):
        kinesis = aws_stack.connect_to_service('kinesis')
        s3 = aws_stack.connect_to_service('s3')

        aws_stack.create_kinesis_stream(TEST_CHAIN_STREAM1_NAME, delete=True)
        aws_stack.create_kinesis_stream(TEST_CHAIN_STREAM2_NAME, delete=True)
        s3.create_bucket(Bucket=TEST_BUCKET_NAME)

        # deploy test lambdas connected to Kinesis streams
        zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
            libs=TEST_LAMBDA_LIBS)
        testutil.create_lambda_function(func_name=TEST_CHAIN_LAMBDA1_NAME, zip_file=zip_file,
            event_source_arn=get_event_source_arn(TEST_CHAIN_STREAM1_NAME))
        testutil.create_lambda_function(func_name=TEST_CHAIN_LAMBDA2_NAME, zip_file=zip_file,
            event_source_arn=get_event_source_arn(TEST_CHAIN_STREAM2_NAME))

        # publish test record
        test_data = {'test_data': 'forward_chain_data_%s with \'quotes\\"' % short_uid()}
        data = clone(test_data)
        data[lambda_integration.MSG_BODY_MESSAGE_TARGET] = 'kinesis:%s' % TEST_CHAIN_STREAM2_NAME
        kinesis.put_record(Data=to_bytes(json.dumps(data)), PartitionKey='testId', StreamName=TEST_CHAIN_STREAM1_NAME)

        def check_results():
            all_objects = testutil.list_all_s3_objects()
            testutil.assert_objects(test_data, all_objects)

        # check results
        retry(check_results, retries=5, sleep=3)

        # clean up
        kinesis.delete_stream(StreamName=TEST_CHAIN_STREAM1_NAME)
        kinesis.delete_stream(StreamName=TEST_CHAIN_STREAM2_NAME)

    def test_sqs_batch_lambda_forward(self):
        sqs = aws_stack.connect_to_service('sqs')
        lambda_api = aws_stack.connect_to_service('lambda')

        lambda_name_queue_batch = 'lambda_queue_batch-%s' % short_uid()

        # deploy test lambda connected to SQS queue
        sqs_queue_info = testutil.create_sqs_queue(lambda_name_queue_batch)
        queue_url = sqs_queue_info['QueueUrl']
        resp = testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=lambda_name_queue_batch,
            event_source_arn=sqs_queue_info['QueueArn'],
            libs=TEST_LAMBDA_LIBS
        )

        event_source_id = resp['CreateEventSourceMappingResponse']['UUID']
        lambda_api.update_event_source_mapping(
            UUID=event_source_id,
            BatchSize=5
        )

        messages_to_send = [
            {
                'Id': 'message{:02d}'.format(i),
                'MessageBody': 'msgBody{:02d}'.format(i),
                'MessageAttributes': {
                    'CustomAttribute': {
                        'DataType': 'String',
                        'StringValue': 'CustomAttributeValue{:02d}'.format(i)
                    }
                }
            }
            for i in range(1, 12)
        ]

        # send 11 messages (which should get split into 3 batches)
        sqs.send_message_batch(QueueUrl=queue_url, Entries=messages_to_send[:10])
        sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=messages_to_send[10]['MessageBody'],
            MessageAttributes=messages_to_send[10]['MessageAttributes']
        )

        def wait_for_done():
            attributes = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=[
                    'ApproximateNumberOfMessages',
                    'ApproximateNumberOfMessagesDelayed',
                    'ApproximateNumberOfMessagesNotVisible'
                ],
            )['Attributes']
            msg_count = int(attributes.get('ApproximateNumberOfMessages'))
            self.assertEqual(msg_count, 0, 'expecting queue to be empty')

            delayed_count = int(attributes.get('ApproximateNumberOfMessagesDelayed'))
            if delayed_count != 0:
                LOGGER.warning('SQS delayed message count (actual/expected): %s/%s' % (delayed_count, 0))

            not_visible_count = int(attributes.get('ApproximateNumberOfMessagesNotVisible'))
            if not_visible_count != 0:
                LOGGER.warning('SQS messages not visible (actual/expected): %s/%s' % (not_visible_count, 0))

            self.assertEqual(delayed_count, 0, 'no messages waiting for retry')
            self.assertEqual(delayed_count + not_visible_count, 0, 'no in flight messages')

        # wait for the queue to drain (max 60s)
        retry(wait_for_done, retries=12, sleep=5.0)

        events = get_lambda_log_events(lambda_name_queue_batch, 10)
        self.assertEqual(len(events), 3, 'expected 3 lambda invocations')

        testutil.delete_lambda_function(lambda_name_queue_batch)
        sqs.delete_queue(QueueUrl=queue_url)

    def test_scheduled_lambda(self):
        def check_invocation(*args):
            log_events = LambdaTestBase.get_lambda_logs(self.scheduled_lambda_name)
            self.assertGreater(len(log_events), 0)

        # wait for up to 1 min for invocations to get triggered
        retry(check_invocation, retries=14, sleep=5)


# ---------------
# HELPER METHODS
# ---------------


def get_event_source_arn(stream_name):
    kinesis = aws_stack.connect_to_service('kinesis')
    return kinesis.describe_stream(StreamName=stream_name)['StreamDescription']['StreamARN']


def get_lambda_invocations_count(lambda_name, metric=None, period=None, start_time=None, end_time=None):
    metric = get_lambda_metrics(lambda_name, metric, period, start_time, end_time)
    if not metric['Datapoints']:
        return 0
    return metric['Datapoints'][-1]['Sum']


def get_lambda_metrics(func_name, metric=None, period=None, start_time=None, end_time=None):
    metric = metric or 'Invocations'
    cloudwatch = aws_stack.connect_to_service('cloudwatch')
    period = period or 600
    end_time = end_time or datetime.now()
    if start_time is None:
        start_time = end_time - timedelta(seconds=period)
    return cloudwatch.get_metric_statistics(
        Namespace='AWS/Lambda',
        MetricName=metric,
        Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
        Period=period,
        StartTime=start_time,
        EndTime=end_time,
        Statistics=['Sum']
    )
