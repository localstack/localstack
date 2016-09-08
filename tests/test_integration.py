#!/usr/bin/env python

"""
Integration test for local cloud stack.

Usage:
    test_integration.py [ --env=<> ]

Options:
    -h --help     Show this screen.

"""

import __init__
import base64
import json
import time
import sys
from docopt import docopt
from localstack.utils.common import *
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE
from localstack.mock import infra
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME
TEST_TABLE_NAME = 'test_stream_table'
TEST_LAMBDA_NAME = 'test_lambda'

DEFAULT_LAMBDA_RUNTIME = 'python2.7'
DEFAULT_LAMBDA_STARTING_POSITION = 'LATEST'
DEFAULT_LAMBDA_HANDLER = 'handler.handler'
LAMBDA_EXECUTION_TIMEOUT_SECS = 60

ARCHIVE_DIR_PATTERN = '/tmp/lambda.archive.*'
MAIN_SCRIPT_NAME = 'handler.py'

EVENTS = []

PARTITION_KEY = 'id'


def create_dynamodb_table(table_name, partition_key, env=None, stream_view_type=None):
    """Utility method to create a DynamoDB table"""

    dynamodb = aws_stack.connect_to_service('dynamodb', env=env, client=True)
    stream_spec = {'StreamEnabled': False}
    key_schema = [{
        'AttributeName': partition_key,
        'KeyType': 'HASH'
    }]
    attr_defs = [{
        'AttributeName': partition_key,
        'AttributeType': 'S'
    }]
    if stream_view_type is not None:
        stream_spec = {
            'StreamEnabled': True,
            'StreamViewType': stream_view_type
        }
    table = dynamodb.create_table(TableName=table_name, KeySchema=key_schema,
        AttributeDefinitions=attr_defs, ProvisionedThroughput={
            'ReadCapacityUnits': 10, 'WriteCapacityUnits': 10
        },
        StreamSpecification=stream_spec
    )
    time.sleep(2)
    return table


def create_lambda_archive(script, stream=None, get_content=False):
    """Utility method to create a Lambda function archive"""

    tmp_dir = ARCHIVE_DIR_PATTERN.replace('*', short_uid())
    run('mkdir -p %s' % tmp_dir)
    script_file = '%s/%s' % (tmp_dir, MAIN_SCRIPT_NAME)
    zip_file_name = 'archive.zip'
    zip_file = '%s/%s' % (tmp_dir, zip_file_name)
    save_file(script_file, script)
    # create zip file
    run('cd %s && zip -r %s *' % (tmp_dir, zip_file_name))
    if not get_content:
        TMP_FILES.append(tmp_dir)
        return zip_file
    zip_file_content = None
    with open(zip_file, "rb") as file_obj:
        zip_file_content = file_obj.read()
    run('rm -r %s' % tmp_dir)
    return zip_file_content


def create_lambda_function(func_name, zip_file, event_source_arn, handler=DEFAULT_LAMBDA_HANDLER,
        starting_position=DEFAULT_LAMBDA_STARTING_POSITION):
    """Utility method to create a new function via the Lambda API"""

    client = aws_stack.connect_to_service('lambda')
    # create function
    result = client.create_function(
        FunctionName=func_name,
        Runtime=DEFAULT_LAMBDA_RUNTIME,
        Handler=handler,
        Role=LAMBDA_TEST_ROLE,
        Code={
            'ZipFile': zip_file
        },
        Timeout=LAMBDA_EXECUTION_TIMEOUT_SECS
    )
    # create event source mapping
    client.create_event_source_mapping(
        FunctionName=func_name,
        EventSourceArn=event_source_arn,
        StartingPosition=starting_position
    )


def start_test(env=ENV_DEV):
    try:
        # setup environment
        spawn_thread = True
        if env == ENV_DEV:
            def do_start_infra(params):
                infra.start_infra(async=True)
            if spawn_thread:
                thread = FuncThread(do_start_infra, None)
                thread.start()
                time.sleep(6)
            else:
                do_start_infra()

        dynamodb = aws_stack.connect_to_resource('dynamodb', env=env)
        dynamodbstreams = aws_stack.connect_to_service('dynamodbstreams', env=env)
        kinesis = aws_stack.connect_to_service('kinesis', env=env)

        print('Creating stream...')
        aws_stack.create_kinesis_stream(TEST_STREAM_NAME)

        # subscribe to inbound Kinesis stream
        def process_records(records):
            EVENTS.extend(records)

        # start the KCL client process in the background
        kinesis_connector.listen_to_kinesis(TEST_STREAM_NAME, listener_func=process_records)

        print("Sleep some time (to give the Kinesis consumer enough time to come up)")
        time.sleep(25)

        # create table with stream forwarding config
        create_dynamodb_table(TEST_TABLE_NAME, partition_key=PARTITION_KEY,
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
        zip_file = create_lambda_archive(script, get_content=True)
        create_lambda_function(func_name=TEST_LAMBDA_NAME, zip_file=zip_file, event_source_arn=event_source_arn)

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
        time.sleep(10)

        print('DynamoDB updates retrieved via Kinesis (actual/expected): %s/%s' % (len(EVENTS), num_events))
        assert len(EVENTS) == num_events

        print("Test finished successfully")
        cleanup(env=env)

    except KeyboardInterrupt, e:
        infra.KILLED = True
    finally:
        print("Shutdown")
        cleanup(files=True, env=env)
        infra.stop_infra()


if __name__ == '__main__':
    args = docopt(__doc__)
    env = args['--env'] or ENV_DEV
    start_test(env=env)
