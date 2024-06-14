import json
import os

import pytest
from botocore.config import Config
from botocore.exceptions import ClientError

from localstack.testing.aws.lambda_utils import _await_dynamodb_table_active
from localstack.testing.pytest import markers
from localstack.utils.aws import arns
from localstack.utils.aws.arns import get_partition
from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry
from tests.aws.services.s3.conftest import TEST_S3_IMAGE

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_LAMBDA_PYTHON_TRIGGERED_S3 = os.path.join(
    THIS_FOLDER, "../lambda_", "functions", "lambda_triggered_by_s3.py"
)


@pytest.mark.skipif(condition=TEST_S3_IMAGE, reason="Lambda not enabled in S3 image")
class TestS3NotificationsToLambda:
    @markers.aws.validated
    def test_create_object_put_via_dynamodb(
        self,
        s3_create_bucket,
        create_lambda_function,
        create_role,
        dynamodb_create_table,
        snapshot,
        aws_client,
    ):
        snapshot.add_transformer(snapshot.transform.s3_dynamodb_notifications())

        bucket_name = s3_create_bucket()
        function_name = f"func-{short_uid()}"
        table_name = f"table-{short_uid()}"
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
        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=f"arn:{get_partition(aws_client.iam.meta.region_name)}:iam::aws:policy/AWSLambdaExecute",
        )
        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=f"arn:{get_partition(aws_client.iam.meta.region_name)}:iam::aws:policy/AmazonDynamoDBFullAccess",
        )
        lambda_role = role["Role"]["Arn"]

        function = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3, func_name=function_name, role=lambda_role
        )["CreateFunctionResponse"]

        aws_client.lambda_.add_permission(
            StatementId="1",
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        # this test uses dynamodb as an intermediary to get the notifications from the lambda back to the test
        dynamodb_create_table(
            table_name=table_name, partition_key="uuid", client=aws_client.dynamodb
        )

        aws_client.s3.put_bucket_notification_configuration(
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
        aws_client.s3.put_object(Bucket=bucket_name, Key=table_name, Body="something..")

        def check_table():
            rs = aws_client.dynamodb.scan(TableName=table_name)
            assert len(rs["Items"]) == 1
            event = rs["Items"][0]["data"]
            snapshot.match("table_content", event)

        retry(check_table, retries=5, sleep=1)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..data.M.s3.M.object.M.eTag.S",
            "$..data.M.s3.M.object.M.size.N",
        ],  # TODO presigned-post sporadic failures in CI Pipeline
    )
    def test_create_object_by_presigned_request_via_dynamodb(
        self,
        s3_create_bucket,
        create_lambda_function,
        dynamodb_create_table,
        create_role,
        snapshot,
        aws_client,
        aws_client_factory,
    ):
        snapshot.add_transformer(snapshot.transform.s3_dynamodb_notifications())

        bucket_name = s3_create_bucket()
        function_name = f"func-{short_uid()}"
        table_name = f"table-{short_uid()}"
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
        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=f"arn:{get_partition(aws_client.iam.meta.region_name)}:iam::aws:policy/AWSLambdaExecute",
        )
        aws_client.iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn=f"arn:{get_partition(aws_client.iam.meta.region_name)}:iam::aws:policy/AmazonDynamoDBFullAccess",
        )
        lambda_role = role["Role"]["Arn"]

        function = create_lambda_function(
            handler_file=TEST_LAMBDA_PYTHON_TRIGGERED_S3, func_name=function_name, role=lambda_role
        )["CreateFunctionResponse"]

        aws_client.lambda_.add_permission(
            StatementId="1",
            FunctionName=function_name,
            Action="lambda:InvokeFunction",
            Principal="s3.amazonaws.com",
        )

        dynamodb_create_table(
            table_name=table_name, partition_key="uuid", client=aws_client.dynamodb
        )
        _await_dynamodb_table_active(aws_client.dynamodb, table_name)

        aws_client.s3.put_bucket_notification_configuration(
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

        s3_sigv4_client = aws_client_factory(
            config=Config(signature_version="s3v4"),
        ).s3
        put_url = s3_sigv4_client.generate_presigned_url(
            ClientMethod="put_object", Params={"Bucket": bucket_name, "Key": table_name}
        )
        requests.put(put_url, data="by_presigned_put")

        presigned_post = s3_sigv4_client.generate_presigned_post(Bucket=bucket_name, Key=table_name)
        # method 1
        requests.post(
            presigned_post["url"],
            data=presigned_post["fields"],
            files={"file": b"by post method 1"},
        )

        def check_table():
            rs = aws_client.dynamodb.scan(TableName=table_name)
            items = sorted(rs["Items"], key=lambda x: x["data"]["M"]["eventName"]["S"])
            assert len(rs["Items"]) == 2
            snapshot.match("items", items)

        retry(check_table, retries=20, sleep=2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Error.ArgumentName1",
            "$..Error.ArgumentValue1",
            "$..Error.ArgumentName",
            "$..Error.ArgumentValue",
        ],
    )
    def test_invalid_lambda_arn(self, s3_create_bucket, account_id, snapshot, aws_client):
        bucket_name = s3_create_bucket()
        config = {
            "LambdaFunctionConfigurations": [
                {
                    "Id": "id123",
                    "Events": ["s3:ObjectCreated:*"],
                }
            ]
        }

        config["LambdaFunctionConfigurations"][0]["LambdaFunctionArn"] = "invalid-queue"
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
                SkipDestinationValidation=False,
            )
        snapshot.match("invalid_not_skip", e.value.response)

        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
                SkipDestinationValidation=True,
            )
        snapshot.match("invalid_skip", e.value.response)

        # set valid but not-existing lambda
        config["LambdaFunctionConfigurations"][0]["LambdaFunctionArn"] = (
            f"{arns.lambda_function_arn('my-lambda', account_id=account_id, region_name=aws_client.s3.meta.region_name)}"
        )
        with pytest.raises(ClientError) as e:
            aws_client.s3.put_bucket_notification_configuration(
                Bucket=bucket_name,
                NotificationConfiguration=config,
            )
        snapshot.match("lambda-does-not-exist", e.value.response)

        aws_client.s3.put_bucket_notification_configuration(
            Bucket=bucket_name, NotificationConfiguration=config, SkipDestinationValidation=True
        )
        config = aws_client.s3.get_bucket_notification_configuration(Bucket=bucket_name)
        snapshot.match("skip_destination_validation", config)
