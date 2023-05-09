import pytest
from botocore.exceptions import ClientError, ParamValidationError, WaiterError

from localstack.utils.strings import short_uid

# TODO: how to generate a valid resource?

TEMPLATE = """
Parameters:
  TopicName:
    Type: String

  PropertyName:
    Type: String

Resources:
  MyTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Ref TopicName

Outputs:
  TopicName:
    Value:
        Fn::GetAtt:
        - "MyTopic"
        - !Ref PropertyName

  ResourceRef:
    Value: !Ref MyTopic
"""

RESOURCE_SCHEMA_ATTRIBUTES = {
    "ContentBasedDeduplication",
    "DataProtectionPolicy",
    "DisplayName",
    "FifoTopic",
    "KmsMasterKeyId",
    "Name",
    "SignatureVersion",
    "Subscription",
    "Tags",
    "TracingConfig",
}

DOCUMENTATION_ATTRIBUTES = {
    "TopicName",
    "TopicArn",
}

GLOBAL_ATTRIBUTES = {
    "Arn",
    "Id",
}

ATTRIBUTES = set(
    list(GLOBAL_ATTRIBUTES) + list(RESOURCE_SCHEMA_ATTRIBUTES) + list(DOCUMENTATION_ATTRIBUTES)
)


@pytest.mark.parametrize("attribute", ATTRIBUTES)
def test_getting_all_attributes(attribute, aws_client, snapshot, cleanups):
    cfn_client = aws_client.cloudformation
    stack_name = f"cfnv2-test-stack-{short_uid()}"

    try:
        create_stack_result = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=TEMPLATE,
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": f"topic-{short_uid()}"},
                {"ParameterKey": "PropertyName", "ParameterValue": attribute},
            ],
        )
    except ClientError as e:
        snapshot.match("create-stack-exc", e.response)
        return
    except ParamValidationError as e:
        snapshot.match("create-stack-exc", {"args": e.args, "kwargs": e.kwargs})
        return

    stack_arn = create_stack_result["StackId"]
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))

    try:
        cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
    except WaiterError:
        pass

    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe-stack", describe_stack)

    if describe_stack["Stacks"][0]["StackStatus"] != "CREATE_COMPLETE":
        stack_events = (
            cfn_client.get_paginator("describe_stack_events")
            .paginate(StackName=stack_arn)
            .build_full_result()
        )
        snapshot.match("stack-events", stack_events)
