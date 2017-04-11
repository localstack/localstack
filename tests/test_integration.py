import base64
import json
import time
import sys
from docopt import docopt
from localstack.utils import testutil
from localstack.utils.common import *
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE
from localstack.mock import infra
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME = 'test_lambda'
TEST_FIREHOSE_NAME = 'test_firehose'

EVENTS = []

PARTITION_KEY = 'id'


def test_firehose_s3(env=ENV_DEV):

    s3_resource = aws_stack.connect_to_resource('s3', env=env)
    s3_client = aws_stack.connect_to_service('s3', env=env)
    firehose = aws_stack.connect_to_service('firehose', env=env)

    s3_prefix = '/testdata'
    bucket_name = 'test_bucket'
    test_data = b'{"test": "data123"}'
    # create Firehose stream
    stream = firehose.create_delivery_stream(
        DeliveryStreamName=TEST_FIREHOSE_NAME,
        S3DestinationConfiguration={
            'RoleARN': aws_stack.iam_resource_arn('firehose'),
            'BucketARN': aws_stack.s3_bucket_arn(bucket_name),
            'Prefix': s3_prefix
        }
    )
    # create target S3 bucket
    s3_resource.create_bucket(Bucket=bucket_name)

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


def test_kinesis_lambda_ddb_streams(env=ENV_DEV):

    dynamodb = aws_stack.connect_to_resource('dynamodb', env=env)
    dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams', env=env)
    kinesis = aws_stack.connect_to_service('kinesis', env=env)

    print('Creating stream...')
    aws_stack.create_kinesis_stream(TEST_STREAM_NAME)

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

    # list streams and make sure the table stream is there
    streams = dynamodbstreams.list_streams()
    event_source_arn = None
    for stream in streams['Streams']:
        if stream['TableName'] == TEST_TABLE_NAME:
            event_source_arn = stream['StreamArn']
    assert event_source_arn

    # deploy test lambda
    script = load_file(os.path.join(LOCALSTACK_ROOT_FOLDER, 'tests', 'lambdas', 'lambda_integration.py'))
    zip_file = testutil.create_lambda_archive(script, get_content=True)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME, zip_file=zip_file, event_source_arn=event_source_arn)

    # put items to table
    num_events = 10
    print('Putting %s items to table...' % num_events)
    table = dynamodb.Table(TEST_TABLE_NAME)
    for i in range(0, num_events):
        table.put_item(Item={
            PARTITION_KEY: 'testId123',
            'data': 'foobar123'
        })

    print("Waiting some time before finishing test.")
    time.sleep(5)

    print('DynamoDB updates retrieved via Kinesis (actual/expected): %s/%s' % (len(EVENTS), num_events))
    if len(EVENTS) != num_events:
        print('ERROR receiving DynamoDB updates. Running processes:')
        print(run("ps aux | grep 'python\|java\|node'"))
    assert len(EVENTS) == num_events
