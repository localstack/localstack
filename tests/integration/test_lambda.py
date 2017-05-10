import os
import json
from io import BytesIO
from localstack.utils import testutil
from localstack.utils.common import *
from localstack.mock.apis import lambda_api
from localstack.utils.aws import aws_stack

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_integration.py')


def test_upload_lambda_from_s3():

    s3_client = aws_stack.connect_to_service('s3')
    lambda_client = aws_stack.connect_to_service('lambda')

    lambda_name = 'test_lambda_%s' % short_uid()
    bucket_name = 'test_bucket_lambda'
    bucket_key = 'test_lambda.zip'

    # upload zip file to S3
    zip_file = testutil.create_zip_file(TEST_LAMBDA_PYTHON, get_content=True)
    s3_client.create_bucket(Bucket=bucket_name)
    s3_client.upload_fileobj(BytesIO(zip_file), bucket_name, bucket_key)

    # create lambda function
    lambda_client.create_function(
        FunctionName=lambda_name,
        Runtime=lambda_api.LAMBDA_RUNTIME_PYTHON27,
        Role='r1',
        Handler='lambda_integration.handler',
        Code={
            'S3Bucket': bucket_name,
            'S3Key': bucket_key
        }
    )

    # invoke lambda function
    data_before = b'{"foo": "bar"}'
    result = lambda_client.invoke(FunctionName=lambda_name, Payload=data_before)
    data_after = result['Payload'].read()
    assert json.loads(to_str(data_before)) == json.loads(to_str(data_after))
