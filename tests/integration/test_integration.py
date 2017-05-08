import base64
import json
import time
import sys
import os
from io import BytesIO
from six.moves import cStringIO as StringIO
from docopt import docopt
from nose.tools import assert_raises
from localstack.utils import testutil
from localstack.utils.common import *
from localstack.config import HOSTNAME, PORT_SQS
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE, TEST_AWS_ACCOUNT_ID
from localstack.mock import infra
from localstack.mock.apis.lambda_api import LAMBDA_RUNTIME_NODEJS, LAMBDA_RUNTIME_PYTHON27, use_docker
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_LAMBDA_SOURCE_STREAM_NAME = 'test_source_stream'
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME_DDB = 'test_lambda_ddb'
TEST_LAMBDA_NAME_STREAM_PY = 'test_lambda_py'
TEST_LAMBDA_NAME_STREAM_JS = 'test_lambda_js'
TEST_FIREHOSE_NAME = 'test_firehose'
TEST_BUCKET_NAME = 'test_bucket'
TEST_BUCKET_NAME_WITH_NOTIFICATIONS = 'test_bucket_2'
TEST_QUEUE_NAME = 'test_queue'

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_NODEJS = load_file(os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.js'))
TEST_LAMBDA_PYTHON = load_file(os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py'))

EVENTS = []

PARTITION_KEY = 'id'


def test_firehose_s3():

    env = ENV_DEV
    s3_resource = aws_stack.connect_to_resource('s3', env=env)
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
    testutil.assert_objects(json.loads(to_str(test_data)), all_objects)


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
    test_data = b'{"test": "bucket_notification"}'
    s3_client.upload_fileobj(BytesIO(test_data), TEST_BUCKET_NAME_WITH_NOTIFICATIONS, test_prefix)

    # receive, assert, and delete message from SQS
    response = sqs_client.receive_message(QueueUrl=queue_url)
    messages = [json.loads(to_str(m['Body'])) for m in response['Messages']]
    testutil.assert_objects({'name': TEST_BUCKET_NAME_WITH_NOTIFICATIONS}, messages)
    for message in response['Messages']:
        sqs_client.delete_message(QueueUrl=queue_url, ReceiptHandle=message['ReceiptHandle'])


def test_kinesis_lambda_ddb_streams():

    env = ENV_DEV
    ddb_lease_table_suffix = '-kclapp'
    dynamodb = aws_stack.connect_to_resource('dynamodb', env=env)
    dynamodb_service = aws_stack.connect_to_service('dynamodb', env=env)
    dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams', env=env)
    kinesis = aws_stack.connect_to_service('kinesis', env=env)

    print('Creating test streams...')
    run_safe(lambda: dynamodb_service.delete_table(
        TableName=TEST_STREAM_NAME + ddb_lease_table_suffix), print_error=False)
    aws_stack.create_kinesis_stream(TEST_STREAM_NAME, delete=True)
    aws_stack.create_kinesis_stream(TEST_LAMBDA_SOURCE_STREAM_NAME)

    # subscribe to inbound Kinesis stream
    def process_records(records, shard_id):
        EVENTS.extend(records)

    # start the KCL client process in the background
    kinesis_connector.listen_to_kinesis(TEST_STREAM_NAME, listener_func=process_records,
        wait_until_started=True, ddb_lease_table_suffix=ddb_lease_table_suffix)

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

    # deploy test lambda (Python) connected to DynamoDB Stream
    zip_file = testutil.create_lambda_archive(TEST_LAMBDA_PYTHON, get_content=True,
        libs=['localstack'], runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_DDB,
        zip_file=zip_file, event_source_arn=ddb_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)
    # make sure we cannot create Lambda with same name twice
    assert_raises(Exception, testutil.create_lambda_function, func_name=TEST_LAMBDA_NAME_DDB,
        zip_file=zip_file, event_source_arn=ddb_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)

    # deploy test lambda (Python) connected to Kinesis Stream
    kinesis_event_source_arn = kinesis.describe_stream(
        StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)['StreamDescription']['StreamARN']
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_STREAM_PY,
        zip_file=zip_file, event_source_arn=kinesis_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)

    if use_docker():
        # deploy test lambda (Node.js) connected to Kinesis Stream
        zip_file = testutil.create_lambda_archive(TEST_LAMBDA_NODEJS, get_content=True,
            runtime=LAMBDA_RUNTIME_NODEJS)
        kinesis_event_source_arn = kinesis.describe_stream(
            StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)['StreamDescription']['StreamARN']
        testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_STREAM_JS,
            zip_file=zip_file, event_source_arn=kinesis_event_source_arn, runtime=LAMBDA_RUNTIME_NODEJS)

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

    # get latest records
    latest = aws_stack.kinesis_get_latest_records(TEST_LAMBDA_SOURCE_STREAM_NAME,
        shard_id='shardId-000000000000', count=10)
    assert len(latest) == 10

    print("Waiting some time before finishing test.")
    time.sleep(2)

    num_events = num_events_ddb + num_events_kinesis
    print('DynamoDB and Kinesis updates retrieved (actual/expected): %s/%s' % (len(EVENTS), num_events))
    assert len(EVENTS) == num_events
