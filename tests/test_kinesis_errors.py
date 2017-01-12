import __init__
import boto3
from nose.tools import assert_raises, assert_equal
from botocore.exceptions import ClientError
from localstack import constants
from localstack.utils.common import *
from localstack.mock import infra
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME


def start_test(env=ENV_DEV):
    try:
        if env == ENV_DEV:
            infra.start_infra(async=True, apis=['kinesis'])
            time.sleep(6)
        kinesis = aws_stack.connect_to_service('kinesis', env=env)
        stream = aws_stack.create_kinesis_stream(TEST_STREAM_NAME)

        records = [
            {
                'Data': '0',
                'ExplicitHashKey': '0',
                'PartitionKey': '0'
            }
        ]

        # by default, no errors
        test_no_errors = kinesis.put_records(StreamName='test-stream-1', Records=records)
        assert_equal(test_no_errors['FailedRecordCount'], 0)

        # with a probability of 1, always throw errors
        constants.KINESIS_ERROR_PROBABILITY = 1.0
        assert_raises(ClientError, kinesis.put_records, StreamName='test-stream-1', Records=records)

        # reset probability to zero
        constants.KINESIS_ERROR_PROBABILITY = 0.0

    except KeyboardInterrupt, e:
        infra.KILLED = True
    finally:
        print("Shutdown")
        cleanup(files=True, env=env)
        infra.stop_infra()
