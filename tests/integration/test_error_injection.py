from nose.tools import assert_raises, assert_equal
from botocore.exceptions import ClientError
from localstack import config
from localstack.utils.common import short_uid
from localstack.utils.aws import aws_stack
from localstack.utils import testutil
from .lambdas import lambda_integration
from .test_integration import TEST_TABLE_NAME, PARTITION_KEY

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME


def test_kinesis_error_injection():
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
    assert_equal(test_no_errors['FailedRecordCount'], 0)

    # with a probability of 1, always throw errors
    config.KINESIS_ERROR_PROBABILITY = 1.0
    test_all_errors = kinesis.put_records(StreamName=TEST_STREAM_NAME, Records=records)
    assert_equal(test_all_errors['FailedRecordCount'], 1)

    # reset probability to zero
    config.KINESIS_ERROR_PROBABILITY = 0.0


def test_dynamodb_error_injection():
    dynamodb = aws_stack.connect_to_resource('dynamodb')
    # create table with stream forwarding config
    testutil.create_dynamodb_table(TEST_TABLE_NAME, partition_key=PARTITION_KEY)
    table = dynamodb.Table(TEST_TABLE_NAME)

    # by default, no errors
    test_no_errors = table.put_item(Item={PARTITION_KEY: short_uid(), 'data': 'foobar123'})
    assert_equal(test_no_errors['ResponseMetadata']['HTTPStatusCode'], 200)

    # with a probability of 1, always throw errors
    config.DYNAMODB_ERROR_PROBABILITY = 1.0
    assert_raises(ClientError, table.put_item, Item={PARTITION_KEY: short_uid(), 'data': 'foobar123'})

    # reset probability to zero
    config.DYNAMODB_ERROR_PROBABILITY = 0.0
