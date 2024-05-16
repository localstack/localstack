import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until


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
        parameters={"IsFifo": "true"},
        max_wait=240,
    )
    assert ".fifo" in result.outputs["FooQueueName"]


@markers.aws.validated
def test_sqs_non_fifo_queue_generates_valid_name(deploy_cfn_template):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_fifo_autogenerate_name.yaml"
        ),
        parameters={"IsFifo": "false"},
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


@markers.aws.validated
def test_update_sqs_queuepolicy(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_with_queuepolicy.yaml"
        )
    )

    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
    )
    snapshot.match("policy1", policy["Attributes"]["Policy"])

    updated_stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/sqs_with_queuepolicy_updated.yaml"
        ),
        is_update=True,
        stack_name=stack.stack_name,
    )

    def check_policy_updated():
        policy_updated = aws_client.sqs.get_queue_attributes(
            QueueUrl=updated_stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
        )
        assert policy_updated["Attributes"]["Policy"] != policy["Attributes"]["Policy"]
        return policy_updated

    wait_until(check_policy_updated)

    policy = aws_client.sqs.get_queue_attributes(
        QueueUrl=updated_stack.outputs["QueueUrlOutput"], AttributeNames=["Policy"]
    )

    snapshot.match("policy2", policy["Attributes"]["Policy"])
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
