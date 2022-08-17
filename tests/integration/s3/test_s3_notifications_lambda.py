import json
import os

import pytest

from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_TRIGGERED_S3 = os.path.join(
    THIS_FOLDER, "../awslambda", "functions", "lambda_triggered_by_s3.py"
)


class TestS3NotificationsToLambda:
    @pytest.mark.aws_validated
    def test_create_object_put_via_dynamodb(
        self,
        s3_client,
        dynamodb_client,
        s3_create_bucket,
        lambda_client,
        create_lambda_function,
        iam_client,
        create_role,
        dynamodb_create_table,
        dynamodb_resource,
    ):
        bucket_name = s3_create_bucket()
        function_name = "func-%s" % short_uid()
        table_name = "table-%s" % short_uid()
        role_name = f"test-role-{short_uid()}"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }

        role = create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        iam_client.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSLambdaExecute"
        )
        iam_client.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
        )
        lambda_role = role["Role"]["Arn"]

        function = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3, func_name=function_name, role=lambda_role
        )["CreateFunctionResponse"]

        lambda_client.add_permission(
            StatementId="1",
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        # this test uses dynamodb as an intermediary to get the notifications from the lambda back to the test
        dynamodb_create_table(table_name=table_name, partition_key="uuid", client=dynamodb_client)

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {
                        "LambdaFunctionArn": function["FunctionArn"],
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
            assert event["s3"]["object"]["eTag"].strip('"') == etag.strip('"')

        retry(check_table, retries=5, sleep=1)

    @pytest.mark.aws_validated
    def test_create_object_by_presigned_request_via_dynamodb(
        self,
        s3_client,
        dynamodb_client,
        s3_create_bucket,
        create_lambda_function,
        lambda_client,
        dynamodb_create_table,
        dynamodb_resource,
        iam_client,
        create_role,
    ):

        bucket_name = s3_create_bucket()
        function_name = "func-%s" % short_uid()
        table_name = "table-%s" % short_uid()
        role_name = f"test-role-{short_uid()}"
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                },
            ],
        }
        role = create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
        iam_client.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSLambdaExecute"
        )
        iam_client.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess"
        )
        lambda_role = role["Role"]["Arn"]

        function = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3, func_name=function_name, role=lambda_role
        )["CreateFunctionResponse"]

        lambda_client.add_permission(
            StatementId="1",
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        dynamodb_create_table(table_name=table_name, partition_key="uuid", client=dynamodb_client)

        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "LambdaFunctionConfigurations": [
                    {
                        "LambdaFunctionArn": function["FunctionArn"],
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

        table = dynamodb_resource.Table(table_name)

        def check_table():
            rs = table.scan()
            assert len(rs["Items"]) == 2

        retry(check_table, retries=10, sleep=1)
