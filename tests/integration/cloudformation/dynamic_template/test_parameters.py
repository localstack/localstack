import os

import pytest

from localstack.testing.aws.cloudformation_utils import load_template_raw
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.sync import wait_until

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


def test_create_stack_with_ssm_parameters(cfn_client, ssm_client, sns_client, deploy_cfn_template):
    parameter_name = f"ls-param-{short_uid()}"
    parameter_value = f"ls-param-value-{short_uid()}"
    parameter_logical_id = "parameter123"
    ssm_client.put_parameter(Name=parameter_name, Value=parameter_value, Type="String")
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/dynamicparameter_ssm_string.yaml"
        ),
        template_mapping={"parameter_name": parameter_name},
    )

    stack_description = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0]
    assert stack_description is not None
    assert stack_description["Parameters"][0]["ParameterKey"] == parameter_logical_id
    assert stack_description["Parameters"][0]["ParameterValue"] == parameter_name
    assert stack_description["Parameters"][0]["ResolvedValue"] == parameter_value

    topics = sns_client.list_topics()
    topic_arns = [t["TopicArn"] for t in topics["Topics"]]
    assert any(parameter_value in t for t in topic_arns)


def test_resolve_ssm(
    create_parameter,
    deploy_cfn_template,
):
    parameter_key = f"param-key-{short_uid()}"
    parameter_value = f"param-value-{short_uid()}"
    create_parameter(Name=parameter_key, Value=parameter_value, Type="String")

    result = deploy_cfn_template(
        parameters={"DynamicParameter": parameter_key},
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/resolve_ssm.yaml"),
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
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/resolve_ssm.yaml"),
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
            os.path.dirname(__file__), "../../templates/resolve_ssm_secure.yaml"
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
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/", template_name),
    )

    topic_name = result.outputs["TopicName"]
    assert topic_name == parameter_value


@pytest.mark.xfail(reason="outputs don't behave well in combination with conditions")
@pytest.mark.aws_validated
def test_parameter_usepreviousvalue_behavior(cfn_client, deploy_cfn_template, is_stack_updated):
    template_path = os.path.join(os.path.dirname(__file__), "../../templates/cfn_reuse_param.yaml")

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


@pytest.mark.aws_validated
def test_import_values_across_stacks(deploy_cfn_template, s3_client, cfn_client):
    export_name = f"b-{short_uid()}"

    # create stack #1
    template1 = """
Parameters:
  BucketExportName:
    Type: String
Resources:
  Bucket1:
    Type: AWS::S3::Bucket
    Properties: {}
Outputs:
  BucketName1:
    Value: !Ref Bucket1
    Export:
      Name: !Ref BucketExportName
    """
    result = deploy_cfn_template(template=template1, parameters={"BucketExportName": export_name})
    bucket_name1 = result.outputs.get("BucketName1")
    assert bucket_name1

    # create stack #2
    template2 = """
Parameters:
  BucketExportName:
    Type: String
Resources:
  Bucket2:
    Type: AWS::S3::Bucket
    Properties:
      Tags:
        - Key: test
          Value: !ImportValue
            'Fn::Sub': '${BucketExportName}'
Outputs:
  BucketName2:
    Value: !Ref Bucket2
    """
    result = deploy_cfn_template(template=template2, parameters={"BucketExportName": export_name})
    bucket_name2 = result.outputs.get("BucketName2")
    assert bucket_name2

    # assert that correct bucket tags have been created
    tagging = s3_client.get_bucket_tagging(Bucket=bucket_name2)
    test_tag = [tag for tag in tagging["TagSet"] if tag["Key"] == "test"]
    assert test_tag
    assert test_tag[0]["Value"] == bucket_name1

    # TODO add assert for list-import
