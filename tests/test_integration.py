import base64
import json
import time
import sys
import cStringIO
from docopt import docopt
from localstack.utils import testutil
from localstack.utils.common import *
from localstack.config import HOSTNAME, PORT_SQS
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID
from localstack.mock import infra
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_LAMBDA_SOURCE_STREAM_NAME = 'test_source_stream'
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME = 'test_lambda'
TEST_FIREHOSE_NAME = 'test_firehose'
TEST_BUCKET_NAME = 'test_bucket'
TEST_BUCKET_NAME_WITH_NOTIFICATIONS = 'test_bucket_2'
TEST_QUEUE_NAME = 'test_queue'

EVENTS = []

PARTITION_KEY = 'id'


def test_firehose_s3():

    env = ENV_DEV
    s3_resource = aws_stack.connect_to_resource('s3', env=env)
    s3_client = aws_stack.connect_to_service('s3', env=env)
    firehose = aws_stack.connect_to_service('firehose', env=env)

    s3_prefix = '/testdata'
    test_data = b'{"test": "data123"}'
    # create Firehose stream
    stream = firehose.create_delivery_stream(
        DeliveryStreamName=TEST_FIREHOSE_NAME,
        S3DestinationConfiguration={
            'RoleARN': aws_stack.iam_resource_arn('firehose'),
            'BucketARN': aws_stack.s3_bucket_arn(TEST_BUCKET_NAME),
            'Prefix': s3_prefix
        }
    )
    assert TEST_FIREHOSE_NAME in firehose.list_delivery_streams()['DeliveryStreamNames']
    # create target S3 bucket
    s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME)

    # put records
    firehose.put_record(
        DeliveryStreamName=TEST_FIREHOSE_NAME,
        Record={
            'Data': test_data
        }
    )
    # check records in target bucket
    all_objects = testutil.list_all_s3_objects()
    testutil.assert_objects(json.loads(test_data), all_objects)


def test_bucket_notifications():

    env = ENV_DEV
    s3_resource = aws_stack.connect_to_resource('s3', env=env)
    s3_client = aws_stack.connect_to_service('s3', env=env)
    sqs_client = aws_stack.connect_to_service('sqs', env=env)

    # create test bucket and queue
    s3_resource.create_bucket(Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS)
    sqs_client.create_queue(QueueName=TEST_QUEUE_NAME)

    # create notification on bucket
    queue_url = 'http://%s:%s/%s/%s' % (HOSTNAME, PORT_SQS, TEST_AWS_ACCOUNT_ID, TEST_QUEUE_NAME)
    s3_client.put_bucket_notification_configuration(
        Bucket=TEST_BUCKET_NAME_WITH_NOTIFICATIONS,
        NotificationConfiguration={
            'QueueConfigurations': [
                {
                    'Id': 'id123456',
                    'QueueArn': queue_url,
                    'Events': ['s3:ObjectCreated:*', 's3:ObjectRemoved:Delete']
                }
            ]
        }
    )

    # upload file to S3
    test_prefix = '/testdata'
    test_data = '{"test": "bucket_notification"}'
    s3_client.upload_fileobj(cStringIO.StringIO(test_data), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_prefix)

    # receive, assert, and delete message from SQS
    response = sqs_client.receive_message(QueueUrl=queue_url)
    messages = [json.loads(m['Body']) for m in response['Messages']]
    testutil.assert_objects({'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}, messages)
    for message in response['Messages']:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['ReceiptHandle'])


def test_kinesis_lambda_ddb_streams():

    env = ENV_DEV
    dynamodb = aws_stack.connect_to_resource('dynamodb', env=env)
    dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams', env=env)
    kinesis = aws_stack.connect_to_service('kinesis', env=env)

    print('Creating test streams...')
    aws_stack.create_kinesis_stream(TEST_STREAM_NAME)
    aws_stack.create_kinesis_stream(TEST_LAMBDA_SOURCE_STREAM_NAME)

    # subscribe to inbound Kinesis stream
    def process_records(records, shard_id):
        EVENTS.extend(records)

    # start the KCL client process in the background
    kinesis_connector.listen_to_kinesis(TEST_STREAM_NAME, listener_func=process_records,
        wait_until_started=True)

    print("Kinesis consumer initialized.")

    # create table with stream forwarding config
    testutil.create_dynamodb_table(TEST_TABLE_NAME, partition_key=PARTITION_KEY,
        env=env, stream_view_type='NEW_AND_OLD_IMAGES')

    # list DDB streams and make sure the table stream is there
    streams = dynamodbstreams.list_streams()
    ddb_event_source_arn = None
    for stream in streams['Streams']:
        if stream['TableName'] == TEST_TABLE_NAME:
            ddb_event_source_arn = stream['StreamArn']
    assert ddb_event_source_arn

    # deploy test lambda connected to DynamoDB Stream
    script = load_file(os.path.join(LOCALSTACK_ROOT_FOLDER, 'tests', 'lambdas', 'lambda_integration.py'))
    zip_file = testutil.create_lambda_archive(script, get_content=True)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME,
        zip_file=zip_file, event_source_arn=ddb_event_source_arn)

    # deploy test lambda connected to Kinesis Stream
    kinesis_event_source_arn = kinesis.describe_stream(
        StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)['StreamDescription']['StreamARN']
    testutil.create_lambda_function(func_name=TEST_LAMBDA_SOURCE_STREAM_NAME,
        zip_file=zip_file, event_source_arn=kinesis_event_source_arn)

    # put items to table
    num_events_ddb = 10
    print('Putting %s items to table...' % num_events_ddb)
    table = dynamodb.Table(TEST_TABLE_NAME)
    for i in range(0, num_events_ddb):
        table.put_item(Item={
            PARTITION_KEY: 'testId%s' % i,
            'data': 'foobar123'
        })

    # put items to stream
    num_events_kinesis = 10
    print('Putting %s items to stream...' % num_events_kinesis)
    kinesis.put_records(
        Records=[
            {
                'Data': '{}',
                'PartitionKey': 'testId%s' % i
            } for i in range(0, num_events_kinesis)
        ],
        StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME
    )

    print("Waiting some time before finishing test.")
    time.sleep(4)

    num_events = num_events_ddb + num_events_kinesis
    print('DynamoDB and Kinesis updates retrieved (actual/expected): %s/%s' % (len(EVENTS), num_events))
    if len(EVENTS) != num_events:
        print('ERROR receiving DynamoDB updates.')
    assert len(EVENTS) == num_events
