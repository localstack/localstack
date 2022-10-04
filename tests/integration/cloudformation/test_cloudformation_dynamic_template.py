import os

import pytest

from localstack.utils.common import short_uid

TEST_TEMPLATE_26_1 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
Outputs:
  TestOutput26:
    Value: !GetAtt MyQueue.Arn
    Export:
      Name: TestQueueArn26
"""
TEST_TEMPLATE_26_2 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MessageQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
      RedrivePolicy:
        deadLetterTargetArn: !ImportValue TestQueueArn26
        maxReceiveCount: 3
Outputs:
  MessageQueueUrl1:
    Value: !ImportValue TestQueueArn26
  MessageQueueUrl2:
    Value: !Ref MessageQueue
"""


# TODO: re-write this
@pytest.mark.skip(reason="flaky due to issues in parameter handling and re-resolving")
def test_stack_imports(deploy_cfn_template, cfn_client, sqs_client):
    result = cfn_client.list_imports(ExportName="_unknown_")
    assert result["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert result["Imports"] == []  # TODO: create test with actual import values!

    queue_name1 = f"q-{short_uid()}"
    queue_name2 = f"q-{short_uid()}"
    template1 = TEST_TEMPLATE_26_1 % queue_name1
    template2 = TEST_TEMPLATE_26_2 % queue_name2
    deploy_cfn_template(template=template1)
    stack2 = deploy_cfn_template(template=template2)

    queue_url1 = sqs_client.get_queue_url(QueueName=queue_name1)["QueueUrl"]
    queue_url2 = sqs_client.get_queue_url(QueueName=queue_name2)["QueueUrl"]

    queues = sqs_client.list_queues().get("QueueUrls", [])
    assert queue_url1 in queues
    assert queue_url2 in queues

    outputs = cfn_client.describe_stacks(StackName=stack2.stack_name)["Stacks"][0]["Outputs"]
    output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl1"][0]
    assert aws_stack.sqs_queue_arn(queue_url1) == output  # TODO
    output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl2"][0]
    assert output == queue_url2



@pytest.mark.parametrize(
    ("intrinsic_fn", "parameter_1", "parameter_2", "expected_bucket_created"),
    [
        ("Fn::And", "0", "0", False),
        ("Fn::And", "0", "1", False),
        ("Fn::And", "1", "0", False),
        ("Fn::And", "1", "1", True),
        ("Fn::Or", "0", "0", False),
        ("Fn::Or", "0", "1", True),
        ("Fn::Or", "1", "0", True),
        ("Fn::Or", "1", "1", True),
    ],
)
def test_intrinsic_functions(
        cfn_client,
        s3_client,
        intrinsic_fn,
        parameter_1,
        parameter_2,
        expected_bucket_created,
        deploy_cfn_template,
):
    bucket_name = f"ls-bucket-{short_uid()}"

    deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/cfn_intrinsic_functions.yaml"
        ),
        parameters={
            "Param1": parameter_1,
            "Param2": parameter_2,
            "BucketName": bucket_name,
        },
        template_mapping={
            "intrinsic_fn": intrinsic_fn,
        },
    )

    buckets = s3_client.list_buckets()
    bucket_names = [b["Name"] for b in buckets["Buckets"]]
    assert (bucket_name in bucket_names) == expected_bucket_created


def test_resolve_ssm(
        create_parameter,
        deploy_cfn_template,
):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"
    create_parameter(Name=parameter_key, Value=parameter_value, Type="String")

    result = deploy_cfn_template(
        parameters={"DynamicParameter": parameter_key},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


def test_resolve_ssm_with_version(ssm_client, cfn_client, create_parameter, deploy_cfn_template):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value_v0 = f"param-value-{short_uid()}"
    parameter_value_v1 = f"param-value-{short_uid()}"
    parameter_value_v2 = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Type="String", Value=parameter_value_v0)

    v1 = ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v1
    )
    ssm_client.put_parameter(
        Name=parameter_key, Overwrite=True, Type="String", Value=parameter_value_v2
    )

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}:{v1['Version']}"},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/resolve_ssm.yaml"),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value_v1


def test_resolve_ssm_secure(create_parameter, cfn_client, deploy_cfn_template):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_parameter(Name=parameter_key, Value=parameter_value, Type="SecureString")

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}"},
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/resolve_ssm_secure.yaml"
        ),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


@pytest.mark.parametrize(
    "template_name", ["resolve_secretsmanager_full.yaml", "resolve_secretsmanager.yaml"]
)
def test_resolve_secretsmanager(
        secretsmanager_client,
        cfn_client,
        create_secret,
        deploy_cfn_template,
        template_name,
):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"

    create_secret(Name=parameter_key, SecretString=parameter_value)

    result = deploy_cfn_template(
        parameters={"DynamicParameter": f"{parameter_key}"},
        template_path=os.path.join(os.path.dirname(__file__), "../templates/", template_name),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


@pytest.mark.xfail(reason="outputs don't behave well in combination with conditions")
@pytest.mark.aws_validated
def test_parameter_usepreviousvalue_behavior(cfn_client, deploy_cfn_template, is_stack_updated):
    template_path = os.path.join(os.path.dirname(__file__), "../templates/cfn_reuse_param.yaml")

    # 1. create with overridden default value. Due to the condition this should neither create the optional topic,
    # nor the corresponding output
    stack = deploy_cfn_template(template_path=template_path, parameters={"DeployParam": "no"})

    stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 2. update using UsePreviousValue. DeployParam should still be "no", still overriding the default and the only
    # change should be the changed tag on the required topic
    cfn_client.update_stack(
        StackName=stack.stack_namestack_name,
        TemplateBody=load_template_raw(template_path),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change"},
            {"ParameterKey": "DeployParam", "UsePreviousValue": True},
        ],
    )
    wait_until(is_stack_updated(stack.stack_id))
    stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 1

    # 3. update with setting the deployparam to "yes" not. The condition will evaluate to true and thus create the
    # topic + output note: for an even trickier challenge for the cloudformation engine, remove the second parameter
    # key. Behavior should stay the same.
    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=load_template_raw(template_path),
        Parameters=[
            {"ParameterKey": "CustomTag", "ParameterValue": "trigger-change-2"},
            {"ParameterKey": "DeployParam", "ParameterValue": "yes"},
        ],
    )
    assert is_stack_updated(stack.stack_id)
    stack_describe_response = cfn_client.describe_stacks(StackName=stack.stack_id)["Stacks"][0]
    assert len(stack_describe_response["Outputs"]) == 2

