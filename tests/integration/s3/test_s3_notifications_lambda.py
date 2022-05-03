import os
import time

from localstack.services.awslambda.lambda_utils import LAMBDA_RUNTIME_PYTHON36
from localstack.utils import testutil
from localstack.utils.aws import aws_stack
from localstack.utils.common import retry, short_uid

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_TRIGGERED_S3 = os.path.join(
    THIS_FOLDER, "../awslambda", "functions", "lambda_triggered_by_s3.py"
)


class TestS3NotificationsToLambda:
    def test_create_object_put_via_dynamodb(
        self, s3_client, lambda_client, dynamodb_client, s3_create_bucket
    ):
        # TODO: inline lambda function
        bucket_name = s3_create_bucket()
        function_name = "func-%s" % short_uid()
        table_name = "table-%s" % short_uid()

        testutil.create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3,
            func_name=function_name,
            runtime=LAMBDA_RUNTIME_PYTHON36,
            client=lambda_client,
        )

        # this test uses dynamodb as an intermediary to get the notifications from the lambda back to the test
        aws_stack.create_dynamodb_table(
            table_name=table_name, partition_key="uuid", client=dynamodb_client
        )

        try:
            s3_client.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration={
                    "LambdaFunctionConfigurations": [
                        {
                            "LambdaFunctionArn": aws_stack.lambda_function_arn(function_name),
                            "Events": ["s3:ObjectCreated:*"],
                        }
                    ]
                },
            )

            # put an object
            obj = s3_client.put_object(Bucket=bucket_name, Key=table_name, Body="something..")
            etag = obj["ETag"]
            time.sleep(2)

            table = aws_stack.connect_to_resource("dynamodb").Table(table_name)

            def check_table():
                rs = table.scan()
                assert len(rs["Items"]) == 1
                return rs

            rs = retry(check_table, retries=4, sleep=3)

            event = rs["Items"][0]["data"]
            assert event["eventSource"] == "aws:s3"
            assert event["eventName"] == "ObjectCreated:Put"
            assert event["s3"]["bucket"]["name"] == bucket_name
            assert event["s3"]["object"]["eTag"] == etag
        finally:
            # clean up
            lambda_client.delete_function(FunctionName=function_name)
            dynamodb_client.delete_table(TableName=table_name)
