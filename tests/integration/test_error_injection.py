import os
import pytest
from botocore.exceptions import ClientError
from localstack import config
from localstack.utils.common import short_uid
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration
from .test_integration import TEST_TABLE_NAME, PARTITION_KEY

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME


def test_kinesis_error_injection():
    if not do_run():
        return

    kinesis = aws_stack.connect_to_service('kinesis')
    aws_stack.create_kinesis_stream(TEST_STREAM_NAME)

    records = [
        {
            'Data': '0',
            'ExplicitHashKey': '0',
            'PartitionKey': '0'
        }
    ]

    # by default, no errors
    test_no_errors = kinesis.put_records(StreamName=TEST_STREAM_NAME, Records=records)
    assert test_no_errors['FailedRecordCount'] == 0

    # with a probability of 1, always throw errors
    config.KINESIS_ERROR_PROBABILITY = 1.0
    test_all_errors = kinesis.put_records(StreamName=TEST_STREAM_NAME, Records=records)
    assert test_all_errors['FailedRecordCount'] == 1

    # reset probability to zero
    config.KINESIS_ERROR_PROBABILITY = 0.0


def get_dynamodb_table():
    dynamodb = aws_stack.connect_to_resource('dynamodb')
    # create table with stream forwarding config
    aws_stack.create_dynamodb_table(TEST_TABLE_NAME, partition_key=PARTITION_KEY)
    return dynamodb.Table(TEST_TABLE_NAME)


def assert_zero_probability_read_error_injection(table, partition_key):
    # by default, no errors
    test_no_errors = table.get_item(Key={PARTITION_KEY: partition_key})
    assert test_no_errors['ResponseMetadata']['HTTPStatusCode'] == 200


def test_dynamodb_error_injection():
    if not do_run():
        return

    table = get_dynamodb_table()

    partition_key = short_uid()
    assert_zero_probability_read_error_injection(table, partition_key)

    # with a probability of 1, always throw errors
    config.DYNAMODB_ERROR_PROBABILITY = 1.0
    with pytest.raises(ClientError):
        table.get_item(Key={PARTITION_KEY: partition_key})

    # reset probability to zero
    config.DYNAMODB_ERROR_PROBABILITY = 0.0


def test_dynamodb_read_error_injection():
    if not do_run():
        return

    table = get_dynamodb_table()

    partition_key = short_uid()
    assert_zero_probability_read_error_injection(table, partition_key)

    # with a probability of 1, always throw errors
    config.DYNAMODB_READ_ERROR_PROBABILITY = 1.0
    with pytest.raises(ClientError):
        table.get_item(Key={PARTITION_KEY: partition_key})

    # reset probability to zero
    config.DYNAMODB_READ_ERROR_PROBABILITY = 0.0


def test_dynamodb_write_error_injection():
    if not do_run():
        return

    table = get_dynamodb_table()

    # by default, no errors
    test_no_errors = table.put_item(Item={PARTITION_KEY: short_uid(), 'data': 'foobar123'})
    assert test_no_errors['ResponseMetadata']['HTTPStatusCode'] == 200

    # with a probability of 1, always throw errors
    config.DYNAMODB_WRITE_ERROR_PROBABILITY = 1.0
    with pytest.raises(ClientError):
        table.put_item(Item={PARTITION_KEY: short_uid(), 'data': 'foobar123'})

    # BatchWriteItem throws ProvisionedThroughputExceededException if ALL items in Batch are Throttled
    with pytest.raises(ClientError):
        table.batch_write_item(RequestItems={table: [{
            'PutRequest': {'Item': {PARTITION_KEY: short_uid(), 'data': 'foobar123'}}}]})

    # reset probability to zero
    config.DYNAMODB_WRITE_ERROR_PROBABILITY = 0.0


def do_run():
    # Only run the tests if the $TEST_ERROR_INJECTION environment variable is set. This is to reduce the
    # testing time, because the injected errors result in retries and timeouts that slow down the tests overall.
    return os.environ.get('TEST_ERROR_INJECTION') in ('true', '1')
