import json
import time
import logging
from datetime import datetime, timedelta
from nose.tools import assert_raises
from localstack.utils import testutil
from localstack.utils.common import load_file, short_uid, clone, to_bytes, to_str, run_safe
from localstack.services.awslambda.lambda_api import LAMBDA_RUNTIME_PYTHON27
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from localstack.utils.cloudwatch import cloudwatch_util
from .lambdas import lambda_integration
from .test_lambda import TEST_LAMBDA_PYTHON, TEST_LAMBDA_LIBS

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_LAMBDA_SOURCE_STREAM_NAME = 'test_source_stream'
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME_DDB = 'test_lambda_ddb'
TEST_LAMBDA_NAME_STREAM = 'test_lambda_stream'
TEST_FIREHOSE_NAME = 'test_firehose'
TEST_BUCKET_NAME = lambda_integration.TEST_BUCKET_NAME
TEST_TOPIC_NAME = 'test_topic'
# constants for forward chain K1->L1->K2->L2
TEST_CHAIN_STREAM1_NAME = 'test_chain_stream_1'
TEST_CHAIN_STREAM2_NAME = 'test_chain_stream_2'
TEST_CHAIN_LAMBDA1_NAME = 'test_chain_lambda_1'
TEST_CHAIN_LAMBDA2_NAME = 'test_chain_lambda_2'

EVENTS = []

PARTITION_KEY = 'id'

# set up logger
LOGGER = logging.getLogger(__name__)


def test_firehose_s3():

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
        }
    )
    assert stream
    assert TEST_FIREHOSE_NAME in firehose.list_delivery_streams()['DeliveryStreamNames']
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


def test_kinesis_lambda_sns_ddb_streams():

    ddb_lease_table_suffix = '-kclapp'
    dynamodb = aws_stack.connect_to_resource('dynamodb')
    dynamodb_service = aws_stack.connect_to_service('dynamodb')
    dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams')
    kinesis = aws_stack.connect_to_service('kinesis')
    sns = aws_stack.connect_to_service('sns')

    LOGGER.info('Creating test streams...')
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

    LOGGER.info('Kinesis consumer initialized.')

    # create table with stream forwarding config
    testutil.create_dynamodb_table(TEST_TABLE_NAME, partition_key=PARTITION_KEY,
        stream_view_type='NEW_AND_OLD_IMAGES')

    # list DDB streams and make sure the table stream is there
    streams = dynamodbstreams.list_streams()
    ddb_event_source_arn = None
    for stream in streams['Streams']:
        if stream['TableName'] == TEST_TABLE_NAME:
            ddb_event_source_arn = stream['StreamArn']
    assert ddb_event_source_arn

    # deploy test lambda connected to DynamoDB Stream
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_DDB,
        zip_file=zip_file, event_source_arn=ddb_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)
    # make sure we cannot create Lambda with same name twice
    assert_raises(Exception, testutil.create_lambda_function, func_name=TEST_LAMBDA_NAME_DDB,
        zip_file=zip_file, event_source_arn=ddb_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)

    # deploy test lambda connected to Kinesis Stream
    kinesis_event_source_arn = kinesis.describe_stream(
        StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)['StreamDescription']['StreamARN']
    testutil.create_lambda_function(func_name=TEST_LAMBDA_NAME_STREAM,
        zip_file=zip_file, event_source_arn=kinesis_event_source_arn, runtime=LAMBDA_RUNTIME_PYTHON27)

    # put items to table
    num_events_ddb = 10
    LOGGER.info('Putting %s items to table...' % num_events_ddb)
    table = dynamodb.Table(TEST_TABLE_NAME)
    for i in range(0, num_events_ddb - 3):
        table.put_item(Item={
            PARTITION_KEY: 'testId%s' % i,
            'data': 'foobar123'
        })
    dynamodb.batch_write_item(RequestItems={TEST_TABLE_NAME: [
        {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123'}}},
        {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123'}}},
        {'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123'}}}
    ]})

    # put items to stream
    num_events_kinesis = 10
    LOGGER.info('Putting %s items to stream...' % num_events_kinesis)
    kinesis.put_records(
        Records=[
            {
                'Data': '{}',
                'PartitionKey': 'testId%s' % i
            } for i in range(0, num_events_kinesis)
        ], StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME
    )

    # put 1 item to stream that will trigger an error in the Lambda
    kinesis.put_record(Data='{"%s": 1}' % lambda_integration.MSG_BODY_RAISE_ERROR_FLAG,
        PartitionKey='testIderror', StreamName=TEST_LAMBDA_SOURCE_STREAM_NAME)

    # create SNS topic, connect it to the Lambda, publish test message
    num_events_sns = 3
    response = sns.create_topic(Name=TEST_TOPIC_NAME)
    sns.subscribe(TopicArn=response['TopicArn'], Protocol='lambda',
        Endpoint=aws_stack.lambda_function_arn(TEST_LAMBDA_NAME_STREAM))
    for i in range(0, num_events_sns):
        sns.publish(TopicArn=response['TopicArn'], Message='test message %s' % i)

    # get latest records
    latest = aws_stack.kinesis_get_latest_records(TEST_LAMBDA_SOURCE_STREAM_NAME,
        shard_id='shardId-000000000000', count=10)
    assert len(latest) == 10

    LOGGER.info('Waiting some time before finishing test.')
    time.sleep(2)

    num_events = num_events_ddb + num_events_kinesis + num_events_sns
    if len(EVENTS) != num_events:
        LOGGER.warning('DynamoDB and Kinesis updates retrieved (actual/expected): %s/%s' % (len(EVENTS), num_events))
    assert len(EVENTS) == num_events

    # check cloudwatch notifications
    stats1 = get_lambda_metrics(TEST_LAMBDA_NAME_STREAM)
    assert len(stats1['Datapoints']) == 2 + num_events_sns
    stats2 = get_lambda_metrics(TEST_LAMBDA_NAME_STREAM, 'Errors')
    assert len(stats2['Datapoints']) == 1
    stats3 = get_lambda_metrics(TEST_LAMBDA_NAME_DDB)
    assert len(stats3['Datapoints']) == 10


def test_kinesis_lambda_forward_chain():
    kinesis = aws_stack.connect_to_service('kinesis')
    s3 = aws_stack.connect_to_service('s3')

    aws_stack.create_kinesis_stream(TEST_CHAIN_STREAM1_NAME, delete=True)
    aws_stack.create_kinesis_stream(TEST_CHAIN_STREAM2_NAME, delete=True)
    s3.create_bucket(Bucket=TEST_BUCKET_NAME)

    # deploy test lambdas connected to Kinesis streams
    zip_file = testutil.create_lambda_archive(load_file(TEST_LAMBDA_PYTHON), get_content=True,
        libs=TEST_LAMBDA_LIBS, runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_CHAIN_LAMBDA1_NAME, zip_file=zip_file,
        event_source_arn=get_event_source_arn(TEST_CHAIN_STREAM1_NAME), runtime=LAMBDA_RUNTIME_PYTHON27)
    testutil.create_lambda_function(func_name=TEST_CHAIN_LAMBDA2_NAME, zip_file=zip_file,
        event_source_arn=get_event_source_arn(TEST_CHAIN_STREAM2_NAME), runtime=LAMBDA_RUNTIME_PYTHON27)

    # publish test record
    test_data = {'test_data': 'forward_chain_data_%s' % short_uid()}
    data = clone(test_data)
    data[lambda_integration.MSG_BODY_MESSAGE_TARGET] = 'kinesis:%s' % TEST_CHAIN_STREAM2_NAME
    kinesis.put_record(Data=to_bytes(json.dumps(data)), PartitionKey='testId', StreamName=TEST_CHAIN_STREAM1_NAME)

    # check results
    time.sleep(5)
    all_objects = testutil.list_all_s3_objects()
    testutil.assert_objects(test_data, all_objects)


# ---------------
# HELPER METHODS
# ---------------

def get_event_source_arn(stream_name):
    kinesis = aws_stack.connect_to_service('kinesis')
    return kinesis.describe_stream(StreamName=stream_name)['StreamDescription']['StreamARN']


def get_lambda_metrics(func_name, metric='Invocations'):
    return cloudwatch_util.get_metric_statistics(
        Namespace='AWS/Lambda',
        MetricName=metric,
        Dimensions=[{'Name': 'FunctionName', 'Value': func_name}],
        Period=60,
        StartTime=datetime.now() - timedelta(minutes=1),
        EndTime=datetime.now(),
        Statistics=['Sum']
    )
