import json
import os

import pytest

from localstack import config
from localstack.utils.strings import short_uid


@pytest.mark.aws_validated
@pytest.mark.skip_snapshot_verify(paths=["$..StreamDescription.StreamModeDetails"])
def test_stream_creation(kinesis_client, cfn_client, deploy_cfn_template, snapshot):
    snapshot.add_transformer(snapshot.transform.resource_name())
    snapshot.add_transformers_list(
        [
            snapshot.transform.key_value("StreamName", "stream-name"),
            snapshot.transform.key_value("ShardId", "shard-id", reference_replacement=False),
            snapshot.transform.key_value("EndingHashKey", "ending-hash-key"),
            snapshot.transform.key_value("StartingSequenceNumber", "sequence-number"),
        ]
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    template = json.dumps(
        {
            "Resources": {
                "TestStream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {"ShardCount": 1},
                },
            },
            "Outputs": {
                "StreamNameFromRef": {"Value": {"Ref": "TestStream"}},
                "StreamArnFromAtt": {"Value": {"Fn::GetAtt": "TestStream.Arn"}},
            },
        }
    )

    stack = deploy_cfn_template(template=template)
    snapshot.match("stack_output", stack.outputs)

    description = cfn_client.describe_stack_resources(StackName=stack.stack_name)
    snapshot.match("resource_description", description)

    stream_name = stack.outputs.get("StreamNameFromRef")
    description = kinesis_client.describe_stream(StreamName=stream_name)
    snapshot.match("stream_description", description)


def test_default_parameters_kinesis(deploy_cfn_template, kinesis_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../templates/kinesis_default.yaml")
    )

    stream_response = kinesis_client.list_streams(ExclusiveStartStreamName=stack.stack_name)

    stream_names = stream_response["StreamNames"]
    assert len(stream_names) > 0

    found = False
    for stream_name in stream_names:
        if stack.stack_name in stream_name:
            found = True
            break
    assert found


TEST_TEMPLATE_12 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  KinesisStreamName:
    Type: String
  DeliveryStreamName:
    Type: String
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: %s
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Action: "*"
            Resource: "*"
  MyBucket:
      Type: AWS::S3::Bucket
      Properties:
        BucketName: !Ref "DeliveryStreamName"
  KinesisStream:
    Type: AWS::Kinesis::Stream
    Properties:
      Name : !Ref "KinesisStreamName"
      ShardCount : 5
  DeliveryStream:
    Type: AWS::KinesisFirehose::DeliveryStream
    Properties:
      DeliveryStreamName: !Ref "DeliveryStreamName"
      DeliveryStreamType: DirectPut
      S3DestinationConfiguration:
        BucketARN: !Ref MyBucket
        BufferingHints:
          IntervalInSeconds: 600
          SizeInMBs: 50
        CompressionFormat: UNCOMPRESSED
        Prefix: raw/
        RoleARN: !GetAtt "MyRole.Arn"
Outputs:
  MyStreamArn:
    Value: !GetAtt "DeliveryStream.Arn"
"""


def test_cfn_handle_kinesis_firehose_resources(
    kinesis_client, firehose_client, deploy_cfn_template
):
    kinesis_stream_name = f"kinesis-stream-{short_uid()}"
    firehose_role_name = f"firehose-role-{short_uid()}"
    firehose_stream_name = f"firehose-stream-{short_uid()}"

    stack = deploy_cfn_template(
        template=TEST_TEMPLATE_12 % firehose_role_name,
        parameters={
            "KinesisStreamName": kinesis_stream_name,
            "DeliveryStreamName": firehose_stream_name,
        },
    )

    assert len(stack.outputs) == 1

    rs = firehose_client.describe_delivery_stream(DeliveryStreamName=firehose_stream_name)
    assert rs["DeliveryStreamDescription"]["DeliveryStreamARN"] == stack.outputs["MyStreamArn"]
    assert rs["DeliveryStreamDescription"]["DeliveryStreamName"] == firehose_stream_name

    rs = kinesis_client.describe_stream(StreamName=kinesis_stream_name)
    assert rs["StreamDescription"]["StreamName"] == kinesis_stream_name

    # clean up
    stack.destroy()

    rs = kinesis_client.list_streams()
    assert kinesis_stream_name not in rs["StreamNames"]
    rs = firehose_client.list_delivery_streams()
    assert firehose_stream_name not in rs["DeliveryStreamNames"]


def test_describe_template(s3_client, cfn_client, s3_create_bucket):
    bucket_name = f"b-{short_uid()}"
    template_body = TEST_TEMPLATE_12 % "test-firehose-role-name"
    s3_create_bucket(Bucket=bucket_name, ACL="public-read")
    s3_client.put_object(Bucket=bucket_name, Key="template.yml", Body=template_body)

    template_url = f"{config.get_edge_url()}/{bucket_name}/template.yml"  # TODO

    params = [
        {"ParameterKey": "KinesisStreamName"},
        {"ParameterKey": "DeliveryStreamName"},
    ]
    # get summary by template URL
    result = cfn_client.get_template_summary(TemplateURL=template_url)
    assert result.get("Parameters") == params
    assert "AWS::S3::Bucket" in result["ResourceTypes"]
    assert result.get("ResourceIdentifierSummaries")
    # get summary by template body
    result = cfn_client.get_template_summary(TemplateBody=template_body)
    assert result.get("Parameters") == params
    assert "AWS::Kinesis::Stream" in result["ResourceTypes"]
    assert result.get("ResourceIdentifierSummaries")


TEST_TEMPLATE_28 = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  EventStream:
    Type: AWS::Kinesis::Stream
    Properties:
      Name: EventStream
      ShardCount: 1
  EventTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName: %s
      AttributeDefinitions:
      - AttributeName: pkey
        AttributeType: S
      KeySchema:
      - AttributeName: pkey
        KeyType: HASH
      BillingMode: PAY_PER_REQUEST
      KinesisStreamSpecification:
        StreamArn: !GetAtt EventStream.Arn
"""


def test_dynamodb_stream_response_with_cf(dynamodb_client, deploy_cfn_template):
    template = TEST_TEMPLATE_28 % "EventTable"
    deploy_cfn_template(template=template)

    response = dynamodb_client.describe_kinesis_streaming_destination(TableName="EventTable")

    assert response.get("TableName") == "EventTable"
    assert len(response.get("KinesisDataStreamDestinations")) == 1
    assert "StreamArn" in response.get("KinesisDataStreamDestinations")[0]
