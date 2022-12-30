import os

import pytest
from botocore.exceptions import ClientError

from localstack.utils.strings import short_uid


def test_sqs_queue_policy(sqs_client, deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sqs_with_queuepolicy.yaml"
        )
    )
    queue_url = result.outputs["QueueUrlOutput"]
    resp = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])
    assert (
        "Statement" in resp["Attributes"]["Policy"]
    )  # just kind of a smoke test to see if its set


@pytest.mark.aws_validated
def test_sqs_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        template_mapping={"is_fifo": "true"},
    )
    assert ".fifo" in result.outputs["FooQueueName"]


# FIXME: doesn't work on AWS. (known bug in cloudformation: https://github.com/aws-cloudformation/cloudformation-coverage-roadmap/issues/165)
def test_sqs_non_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sqs_fifo_autogenerate_name.yaml"
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


def test_cfn_handle_sqs_resource(deploy_cfn_template, sqs_client):
    fifo_queue = f"queue-{short_uid()}.fifo"

    stack = deploy_cfn_template(template=TEST_TEMPLATE_15 % fifo_queue)

    rs = sqs_client.get_queue_url(QueueName=fifo_queue)
    assert rs["ResponseMetadata"]["HTTPStatusCode"] == 200

    queue_url = rs["QueueUrl"]

    rs = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
    attributes = rs["Attributes"]
    assert "ContentBasedDeduplication" in attributes
    assert "FifoQueue" in attributes
    assert attributes["ContentBasedDeduplication"] == "false"
    assert attributes["FifoQueue"] == "true"

    # clean up
    stack.destroy()

    with pytest.raises(ClientError) as ctx:
        sqs_client.get_queue_url(QueueName=fifo_queue)
    assert ctx.value.response["Error"]["Code"] == "AWS.SimpleQueueService.NonExistentQueue"
