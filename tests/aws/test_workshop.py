import time

import aws_cdk as cdk
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

FN_CODE = """
def handler(event, ctx):
    print(event)
"""


class TestCdkWorkshop:

    STACK_NAME = "CdkWorkshop"

    @pytest.fixture(scope="class")
    def infrastructure(self, infrastructure_setup):
        """
        We create 3 resources
        * S3 bucket
        * SQS queue
        * Lambda function

        When an object is put into the S3 bucket, a notification should be sent to the default event bus on EventBridge.
        These events should then be forwarded to both the SQS queue and the Lambda function.

        """
        infra = infrastructure_setup(namespace="CdkTestingWorkshop", force_synth=False)
        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)

        upload_bucket = cdk.aws_s3.Bucket(stack, "bucket", removal_policy=cdk.RemovalPolicy.DESTROY)
        # custom code to avoid a custom resource which would only work with -ext
        # you can ignore the details here but what we're doing is basically using an escape hatch in CDK
        # to fall back to the L1 construct and directly set a variable on the CloudFormation resource
        raw_bucket: cdk.aws_s3.CfnBucket = upload_bucket.node.default_child
        raw_bucket.notification_configuration = (
            cdk.aws_s3.CfnBucket.NotificationConfigurationProperty(
                event_bridge_configuration=cdk.aws_s3.CfnBucket.EventBridgeConfigurationProperty(
                    event_bridge_enabled=True
                )
            )
        )
        queue = cdk.aws_sqs.Queue(stack, "queue")
        cdk.aws_lambda.Function(
            stack,
            "fn",
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_11,
            handler="index.handler",
            code=cdk.aws_lambda.Code.from_inline(FN_CODE),
        )

        # TODO: add a rule here that forwards events (only when an object was created) to the SQS queue and the lambda function
        #       hint: we added a (hopefully) helpful link at the very bottom of the file.

        # TODO: add missing outputs
        cdk.CfnOutput(stack, "QueueUrl", value=queue.queue_url)

        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.needs_fixing
    def test_outputs(self, infrastructure: InfraProvisioner, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        assert outputs.keys() == {"QueueUrl", "BucketName", "FunctionArn", "FunctionName"}

    @pytest.mark.skipif(
        condition=not is_aws_cloud(), reason="only needed when updating stack during development"
    )
    @markers.aws.needs_fixing
    def test_purge_queue(self, infrastructure, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        queue_url = outputs["QueueUrl"]
        aws_client.sqs.purge_queue(QueueUrl=queue_url)
        time.sleep(10)  # should be safe but can technically take up to 60s

    @markers.aws.needs_fixing
    def test_sqs_receives_message(self, infrastructure: InfraProvisioner, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        bucket_name = outputs["BucketName"]
        queue_url = outputs["QueueUrl"]

        key = f"/sqs/{short_uid()}.txt"
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body="hello world")

        def wait_for_sqs_message():
            return aws_client.sqs.receive_message(
                QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=10
            )["Messages"][0]

        msg = retry(wait_for_sqs_message)
        assert key in msg["Body"]
        aws_client.sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])

    @markers.aws.needs_fixing
    def test_lambda_receives_message(self, infrastructure: InfraProvisioner, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        bucket_name = outputs["BucketName"]
        fn_name = outputs["FunctionName"]

        key = f"/lambda/{short_uid()}.txt"
        aws_client.s3.put_object(Bucket=bucket_name, Key=key, Body="hello world")

        def wait_for_lambda_invoke():
            events = (
                aws_client.logs.get_paginator("filter_log_events")
                .paginate(logGroupName=f"/aws/lambda/{fn_name}")
                .build_full_result()["events"]
            )
            filtered_events = [e["message"] for e in events if key in e["message"]]
            assert len(filtered_events) == 1
            return filtered_events[0]

        msg = retry(
            wait_for_lambda_invoke,
            retries=20 if is_aws_cloud() else 5,
            sleep_before=2 if is_aws_cloud() else 0,
        )
        assert key in msg


# this might be helpful
#  event patterns docs: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
