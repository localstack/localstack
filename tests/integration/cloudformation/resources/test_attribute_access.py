import json
import os

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


@pytest.fixture
def valid_topic():
    with open("/home/simon/work/localstack/cfn-schema/schemas/aws-sns-topic.json") as infile:
        schema = json.load(infile)

    required_property_names = schema.get("required", [])
    property_names = list(schema["properties"].keys())

    properties = {}

    for property_name in property_names:
        if property_name not in required_property_names:
            continue

        # TODO

    definition = {"Type": "AWS::SNS::Topic", "Properties": properties}
    return definition


def test_validity(valid_topic):
    assert valid_topic["Properties"] is None


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
        snapshot.match("create_stack_exc", e.response)
        return
    except ParamValidationError as e:
        snapshot.match("create_stack_exc", {"args": e.args, "kwargs": e.kwargs})
        return

    stack_arn = create_stack_result["StackId"]
    cleanups.append(lambda: cfn_client.delete_stack(StackName=stack_arn))

    try:
        cfn_client.get_waiter("stack_create_complete").wait(StackName=stack_arn)
    except WaiterError:
        pass

    describe_stack = cfn_client.describe_stacks(StackName=stack_arn)
    snapshot.match("describe_stack", describe_stack)

    stack_events = (
        cfn_client.get_paginator("describe_stack_events")
        .paginate(StackName=stack_arn)
        .build_full_result()
    )
    snapshot.match("stack_events", stack_events)

    postcreate_original_template = cfn_client.get_template(
        StackName=stack_name, TemplateStage="Original"
    )
    snapshot.match("postcreate_original_template", postcreate_original_template)

    try:
        postcreate_processed_template = cfn_client.get_template(
            StackName=stack_name, TemplateStage="Processed"
        )
        snapshot.match("postcreate_processed_template", postcreate_processed_template)
    except ClientError as e:
        snapshot.match("postcreate_processed_template_exc", e.response)
    except Exception as e:
        snapshot.match("postcreate_processed_template_exc", str(e))

    res = aws_client.cloudformation.describe_stacks(StackName=stack_arn)

    snapshot.match("stack-state", res)


def test_attribute_access(deploy_cfn_template):
    deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../templates/getatt_testing.yaml")
    )
