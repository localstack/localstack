import os

from localstack.utils.aws import aws_stack
from localstack.utils.common import retry
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_TRIGGERED_S3 = os.path.join(
    THIS_FOLDER, "../awslambda", "functions", "lambda_triggered_by_s3.py"
)


class TestS3NotificationsToLambda:
    def test_create_object_put_via_dynamodb(
        self,
        s3_client,
        dynamodb_client,
        s3_create_bucket,
        create_lambda_function,
        dynamodb_create_table,
        dynamodb_resource,
    ):
        # TODO: inline lambda function
        bucket_name = s3_create_bucket()
        function_name = "func-%s" % short_uid()
        table_name = "table-%s" % short_uid()

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3,
            func_name=function_name,
        )

        # this test uses dynamodb as an intermediary to get the notifications from the lambda back to the test
        dynamodb_create_table(table_name=table_name, partition_key="uuid", client=dynamodb_client)

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

        table = dynamodb_resource.Table(table_name)

        def check_table():
            rs = table.scan()
            assert len(rs["Items"]) == 1
            event = rs["Items"][0]["data"]

            assert event["eventSource"] == "aws:s3"
            assert event["eventName"] == "ObjectCreated:Put"
            assert event["s3"]["bucket"]["name"] == bucket_name
            assert event["s3"]["object"]["eTag"] == etag

        retry(check_table, retries=5, sleep=1)

    def test_create_object_by_presigned_request_via_dynamodb(
        self,
        s3_client,
        dynamodb_client,
        s3_create_bucket,
        create_lambda_function,
        dynamodb_create_table,
        dynamodb_resource,
    ):

        bucket_name = s3_create_bucket()
        function_name = "func-%s" % short_uid()
        table_name = "table-%s" % short_uid()

        create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3,
            func_name=function_name,
        )

        dynamodb_create_table(table_name=table_name, partition_key="uuid", client=dynamodb_client)

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

        put_url = s3_client.generate_presigned_url(
            ClientMethod="put_object", Params={"Bucket": bucket_name, "Key": table_name}
        )
        requests.put(put_url, data="by_presigned_put")

        presigned_post = s3_client.generate_presigned_post(Bucket=bucket_name, Key=table_name)
        # method 1
        requests.post(
            presigned_post["url"],
            data=presigned_post["fields"],
            files={"file": b"by post method 1"},
        )

        # method 2
        presigned_post["fields"]["file"] = b"by post method 2"
        requests.post(presigned_post["url"], data=presigned_post["fields"])

        table = dynamodb_resource.Table(table_name)

        def check_table():
            rs = table.scan()
            assert len(rs["Items"]) == 3

        retry(check_table, retries=5, sleep=1)
