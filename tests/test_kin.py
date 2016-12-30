import __init__
import boto3
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE
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

        KINESIS_RETURN_ERRORS = True
        kinesis.put_records(StreamName='test-stream-1', Records=records)
        KINESIS_RETURN_ERRORS = False

    except KeyboardInterrupt, e:
        infra.KILLED = True
    finally:
        print("Shutdown")
        cleanup(files=True, env=env)
        infra.stop_infra()
