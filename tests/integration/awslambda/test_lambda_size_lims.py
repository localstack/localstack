import os
from io import BytesIO

import pytest

from localstack.services.awslambda.lambda_api import LAMBDA_DEFAULT_HANDLER
from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON37
from localstack.utils import testutil
from localstack.utils.common import short_uid

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_ECHO = os.path.join(THIS_FOLDER, "functions", "lambda_echo.py")
FUNCTION_MAX_UNZIPPED_SIZE = 262144000


def generate_sized_python_str(size):
    """Generate a text file of the specified size."""

    with open(TEST_LAMBDA_PYTHON_ECHO, "r") as f:
        py_str = f.read()

    py_str += "#" * (size - len(py_str))

    return py_str


@pytest.mark.aws_validated
class TestLambdaSizeLimits:
    def test_oversized_lambda(self, lambda_client, s3_client, s3_bucket, lambda_su_role, snapshot):
        snapshot.add_transformer(snapshot.transform.lambda_api())

        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = generate_sized_python_str(FUNCTION_MAX_UNZIPPED_SIZE)

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=LAMBDA_RUNTIME_PYTHON37
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        with pytest.raises(lambda_client.exceptions.InvalidParameterValueException) as e:
            lambda_client.create_function(
                FunctionName=function_name,
                Runtime=LAMBDA_RUNTIME_PYTHON37,
                Handler=LAMBDA_DEFAULT_HANDLER,
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )
        snapshot.match("invalid_param_exc", e.value.response)

    # TODO: snapshot
    def test_large_lambda(self, lambda_client, s3_client, s3_bucket, lambda_su_role):
        function_name = f"test_lambda_{short_uid()}"
        bucket_key = "test_lambda.zip"
        code_str = generate_sized_python_str(FUNCTION_MAX_UNZIPPED_SIZE - 1000)

        # upload zip file to S3
        zip_file = testutil.create_lambda_archive(
            code_str, get_content=True, runtime=LAMBDA_RUNTIME_PYTHON37
        )
        s3_client.upload_fileobj(BytesIO(zip_file), s3_bucket, bucket_key)

        # create lambda function
        try:
            result = lambda_client.create_function(
                FunctionName=function_name,
                Runtime=LAMBDA_RUNTIME_PYTHON37,
                Handler=LAMBDA_DEFAULT_HANDLER,
                Role=lambda_su_role,
                Code={"S3Bucket": s3_bucket, "S3Key": bucket_key},
                Timeout=10,
            )

            function_arn = result["FunctionArn"]
            assert testutil.response_arn_matches_partition(lambda_client, function_arn)
        finally:
            lambda_client.delete_function(FunctionName=function_name)
