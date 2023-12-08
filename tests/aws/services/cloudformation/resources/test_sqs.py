import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


@markers.aws.unknown
def test_sqs_queue_policy(deploy_cfn_template, aws_client):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_with_queuepolicy.yaml"
        )
    )
    queue_url = result.outputs["QueueUrlOutput"]
    resp = aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    assert (
        "Statement" in resp["Attributes"]["Policy"]
    )  # just kind of a smoke test to see if its set


@markers.aws.validated
def test_sqs_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        template_mapping={"is_fifo": "true"},
    )
    assert ".fifo" in result.outputs["FooQueueName"]


# FIXME: doesn't work on AWS. (known bug in cloudformation: https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/165)
@markers.aws.unknown
def test_sqs_non_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        template_mapping={"is_fifo": "false"},
        max_wait=240,
    )
    assert ".fifo" not in result.outputs["FooQueueName"]


TEST_TEMPLATE_15 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  FifoQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
        QueueName: %s
        ContentBasedDeduplication: "false"
        FifoQueue: "true"
  NormalQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
        ReceiveMessageWaitTimeSeconds: 1
"""


@markers.aws.unknown
def test_cfn_handle_sqs_resource(deploy_cfn_template, aws_client):
    fifo_queue = f"queue-{short_uid()}.fifo"

    stack = deploy_cfn_template(template=TEST_TEMPLATE_15 % fifo_queue)

    rs = aws_client.sqs.get_queue_url(QueueName=fifo_queue)
    assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

    queue_url = rs["QueueUrl"]

    rs = aws_client.sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
    attributes = rs["Attributes"]
    assert "ContentBasedDeduplication" in attributes
    assert "FifoQueue" in attributes
    assert attributes["ContentBasedDeduplication"] == "false"
    assert attributes["FifoQueue"] == "true"

    # clean up
    stack.destroy()

    with pytest.raises(ClientError) as ctx:
        aws_client.sqs.get_queue_url(QueueName=fifo_queue)
    assert ctx.value.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue"


@markers.aws.validated
def test_update_queue_no_change(deploy_cfn_template, aws_client, snapshot):
    bucket_name = f"bucket-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_queue_update_no_change.yml"
        ),
        parameters={
            "AddBucket": "false",
            "BucketName": bucket_name,
        },
    )
    queue_url = stack.outputs["QueueUrl"]
    queue_arn = stack.outputs["QueueArn"]
    snapshot.add_transformer(snapshot.transform.regex(queue_url, "<queue-url>"))
    snapshot.add_transformer(snapshot.transform.regex(queue_arn, "<queue-arn>"))

    snapshot.match("outputs-1", stack.outputs)

    # deploy a second time with no change to the SQS queue
    updated_stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_queue_update_no_change.yml"
        ),
        is_update=True,
        stack_name=stack.stack_name,
        parameters={
            "AddBucket": "true",
            "BucketName": bucket_name,
        },
    )
    snapshot.match("outputs-2", updated_stack.outputs)
