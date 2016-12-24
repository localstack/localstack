import __init__
from localstack.constants import ENV_DEV, LAMBDA_TEST_ROLE
from localstack.utils.common import *
from localstack.mock import infra
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.aws import aws_stack
from .lambdas import lambda_integration

TEST_STREAM_NAME = lambda_integration.KINESIS_STREAM_NAME

def start_test(env=ENV_DEV):
    try:
        # setup environment
        if env == ENV_DEV:
            infra.start_infra(async=True, apis=['kinesis'])
            time.sleep(6)
        kinesis = aws_stack.connect_to_service('kinesis', env=env)
        stream = aws_stack.create_kinesis_stream(TEST_STREAM_NAME)

        stream.put_records(
            [{
                'StreamName': 'test-stream-1'
            }]
        )
        print 'This should return a response'
        response = infra.update_kinesis(
            'POST',
            '/',
            {u'StreamName': u'test-stream-1'},
            {
                'Host': 'localhost:4568',
                'Authorization': 'AWS4-HMAC-SHA256 Credential=LocalStackDummyAccessKey/20161223/us-east-1/kinesis/aws4_request, SignedHeaders=amz-sdk-invocation-id;amz-sdk-retry;content-length;content-type;host;user-agent;x-amz-date;x-amz-target, Signature=d9e43209de617fdf9716806c8ecac7370f0d341970855c86bbc02e6355f0e5b4',
                'X-Amz-Date': '20161223T204016Z',
                'User-Agent': 'amazon-kinesis-client-library-java-1.7.2 amazon-kinesis-multi-lang-daemon/1.0.1 python/2.7 /tmp/kclipy.0c9cf0f9.processor.py,amazon-kinesis-client-library-java-1.7.2, aws-sdk-java/1.11.14 Mac_OS_X/10.12.2 Java_HotSpot(TM)_64-Bit_Server_VM/25.112-b16/1.8.0_112',
                'amz-sdk-invocation-id': 'bd347038-25b1-8658-8a25-241c44f6e6c0',
                'amz-sdk-retry': '0/0/500',
                'X-Amz-Target': 'Kinesis_20131202.PutRecords',
                'Content-Type': 'application/x-amz-json-1.1',
                'Content-Length': 238,
                'Connection': 'Keep-Alive'
            }
        )
        print 'Response:', response
    except KeyboardInterrupt, e:
        infra.KILLED = True
    finally:
        print("Shutdown")
        cleanup(files=True, env=env)
        infra.stop_infra()
