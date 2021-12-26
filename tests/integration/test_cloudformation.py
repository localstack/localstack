import json
import os
import time
import unittest

import pytest
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_stack import await_stack_completion, deploy_cf_stack
from localstack.utils.cloudformation import template_preparer
from localstack.utils.common import load_file, retry, short_uid, to_str
from localstack.utils.testutil import create_zip_file, list_all_resources

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

TEST_TEMPLATE_1 = os.path.join(THIS_FOLDER, "templates", "template1.yaml")

TEST_TEMPLATE_2 = os.path.join(THIS_FOLDER, "templates", "template2.yaml")

APIGW_INTEGRATION_TEMPLATE = os.path.join(THIS_FOLDER, "templates", "apigateway_integration.json")

TEST_VALID_TEMPLATE = os.path.join(THIS_FOLDER, "templates", "valid_template.json")

TEST_TEMPLATE_3 = (
    """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
"""
    % short_uid()
)

TEST_TEMPLATE_4 = os.path.join(THIS_FOLDER, "templates", "template4.yaml")

TEST_TEMPLATE_5 = os.path.join(THIS_FOLDER, "templates", "template5.yaml")

TEST_ARTIFACTS_BUCKET = "cf-artifacts"
TEST_ARTIFACTS_PATH = "stack.yaml"

TEST_TEMPLATE_6 = os.path.join(THIS_FOLDER, "templates", "template6.yaml")

TEST_TEMPLATE_7 = os.path.join(THIS_FOLDER, "templates", "template7.json")

TEST_TEMPLATE_8 = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "Template for AWS::AWS::Function.",
    "Resources": {
        "S3Bucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": ""}},
        "S3BucketPolicy": {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": {"Ref": "S3Bucket"},
                "PolicyDocument": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": ["*"],
                        }
                    ]
                },
            },
        },
    },
}

TEST_TEMPLATE_9 = (
    """
Parameters:
  gitBranch:
    Type: String
    Default: dev

Mappings:
  AccountInfo:
    "%s":
      ID: 10000000
      ENV: dev

Conditions:
  FeatureBranch:
    Fn::Equals:
      - Ref: gitBranch
      - 'dev'

Resources:
  HeartbeatHandlerLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: 1
      LogGroupName:
        Fn::Join:
          - '_'
          - - '/aws/lambda/AWS_DUB_LAM'
            - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ID ]
            - !If [ FeatureBranch, !Ref "gitBranch", !Ref "AWS::NoValue" ]
            - 'MessageFooHandler'
            - !FindInMap [ AccountInfo, !Ref "AWS::AccountId", ENV ]
"""
    % TEST_AWS_ACCOUNT_ID
)

TEST_TEMPLATE_10 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  DomainName:
    Type: String
    Default: dev
Resources:
  MyElasticsearchDomain:
    Type: AWS::Elasticsearch::Domain
    Properties:
      DomainName: !Ref "DomainName"
      Tags:
        - Key: k1
          Value: v1
        - Key: k2
          Value: v2
Outputs:
  MyElasticsearchDomainEndpoint:
    Value: !GetAtt MyElasticsearchDomain.DomainEndpoint

  MyElasticsearchArn:
    Value: !GetAtt MyElasticsearchDomain.Arn

  MyElasticsearchDomainArn:
    Value: !GetAtt MyElasticsearchDomain.DomainArn

  MyElasticsearchRef:
    Value: !Ref MyElasticsearchDomain
"""

TEST_TEMPLATE_11 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  SecretName:
    Type: String
Resources:
  MySecret:
    Type: AWS::SecretsManager::Secret
    Properties:
      Name: !Ref "SecretName"
      Tags:
        - Key: AppName
          Value: AppA
"""

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

TEST_TEMPLATE_13 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  IamRoleLambdaExecution:
    Type: 'AWS::IAM::Role'
    Properties:
      RoleName: %s
      Path: %s
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
            Resource:
              - !Sub >-
                arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/aws-dev-log:*
  ManagedRolePolicy:
    Type: 'AWS::IAM::ManagedPolicy'
    Properties:
      ManagedPolicyName: %s
      Roles: [!GetAtt IamRoleLambdaExecution.RoleName]
      PolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Action: '*'
            Resource: '*'
"""

TEST_TEMPLATE_14 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  IamRoleLambdaExecution:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument: {}
      Path: %s
"""

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

TEST_TEMPLATE_16 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyBucket:
    Type: 'AWS::S3::Bucket'
    Properties:
      BucketName: %s
  ScheduledRule:
    Type: 'AWS::Events::Rule'
    Properties:
      Name: %s
      ScheduleExpression: rate(10 minutes)
      State: ENABLED
      Targets:
        - Id: TargetBucketV1
          Arn: !GetAtt "MyBucket.Arn"
"""

TEST_TEMPLATE_17 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: %s
      ReceiveMessageWaitTimeSeconds: 0
      VisibilityTimeout: 30
      MessageRetentionPeriod: 1209600

  TestBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: %s
      NotificationConfiguration:
        QueueConfigurations:
          - Event: s3:ObjectCreated:*
            Queue: %s
"""

TEST_TEMPLATE_18 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  TestStateMachine:
    Type: "AWS::StepFunctions::StateMachine"
    Properties:
      RoleArn: %s
      DefinitionString:
        !Sub
        - |-
          {
            "StartAt": "state1",
            "States": {
              "state1": {
                "Type": "Pass",
                "Result": "Hello World",
                "End": true
              }
            }
          }
        - {}
  ScheduledRule:
    Type: AWS::Events::Rule
    Properties:
      ScheduleExpression: "cron(0/1 * * * ? *)"
      State: ENABLED
      Targets:
        - Id: TestStateMachine
          Arn: !Ref TestStateMachine
"""

TEST_CHANGE_SET_BODY = """
Parameters:
  EnvironmentType:
    Type: String
    Default: local
    AllowedValues:
      - prod
      - stage
      - dev
      - local

Conditions:
  IsProd:
    !Equals [ !Ref EnvironmentType, prod ]

Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: {'Fn::If': [IsProd, '_invalid_', '%s']}
"""

TEST_DEPLOY_BODY_1 = os.path.join(THIS_FOLDER, "templates", "deploy_template_1.yaml")

TEST_DEPLOY_BODY_2 = os.path.join(THIS_FOLDER, "templates", "deploy_template_2.yaml")

TEST_DEPLOY_BODY_3 = os.path.join(THIS_FOLDER, "templates", "deploy_template_3.yaml")

TEST_DEPLOY_BODY_4 = os.path.join(THIS_FOLDER, "templates", "deploy_template_4.yaml")

TEST_TEMPLATE_19 = (
    """
Conditions:
  IsPRD:
    Fn::Equals:
    - !Ref AWS::AccountId
    - xxxxxxxxxxxxxx
  IsDEV:
    Fn::Equals:
    - !Ref AWS::AccountId
    - "%s"

Resources:
  TestBucketDev:
    Type: AWS::S3::Bucket
    Condition: IsDEV
    Properties:
      BucketName: cf-dev-{id}
  TestBucketProd:
    Type: AWS::S3::Bucket
    Condition: IsPRD
    Properties:
      BucketName: cf-prd-{id}
"""
    % TEST_AWS_ACCOUNT_ID
)

TEST_TEMPLATE_20 = """
AWSTemplateFormatVersion: 2010-09-09
Description: Test template
Resources:
  LambdaFunction:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: nodejs10.x
      Handler: index.handler
      Role: %s
      Code:
        ZipFile: 'file.zip'
"""

TEST_TEMPLATE_21 = os.path.join(THIS_FOLDER, "templates", "template21.json")

TEST_TEMPLATE_22 = """
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: AWS SAM template with a simple API definition
Resources:
  Api:
    Type: AWS::Serverless::Api
    Properties:
      StageName: prod
  Lambda:
    Type: AWS::Serverless::Function
    Properties:
      Events:
        ApiEvent:
          Type: Api
          Properties:
            Path: /
            Method: get
            RestApiId:
              Ref: Api
      Runtime: python3.7
      Handler: index.handler
      InlineCode: |
        def handler(event, context):
            return {'body': 'Hello World!', 'statusCode': 200}
"""

TEST_TEMPLATE_23 = os.path.join(THIS_FOLDER, "templates", "template23.yaml")

TEST_TEMPLATE_24 = os.path.join(THIS_FOLDER, "templates", "template24.yaml")

TEST_TEMPLATE_25 = os.path.join(THIS_FOLDER, "templates", "template25.yaml")

TEST_TEMPLATE_27 = os.path.join(THIS_FOLDER, "templates", "template27.yaml")

TEST_UPDATE_LAMBDA_FUNCTION_TEMPLATE = os.path.join(
    THIS_FOLDER, "templates", "update_lambda_template.json"
)

SQS_TEMPLATE = os.path.join(THIS_FOLDER, "templates", "fifo_queue.json")

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

TEST_TEMPLATE_27_1 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MyQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
"""
TEST_TEMPLATE_27_2 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  MessageQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
      QueueName: %s
      DelaySeconds: 5
Outputs:
  MessageQueueUrl:
    Value: !Ref MessageQueue
"""

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


def bucket_exists(name):
    s3_client = aws_stack.create_external_boto_client("s3")
    buckets = s3_client.list_buckets()
    for bucket in buckets["Buckets"]:
        if bucket["Name"] == name:
            return True


def queue_exists(name):
    sqs_client = aws_stack.create_external_boto_client("sqs")
    queues = sqs_client.list_queues()
    try:
        url = name if "://" in name else aws_stack.get_sqs_queue_url(name)
    except Exception:
        return False
    for queue_url in queues.get("QueueUrls", []):
        if queue_url == url:
            return queue_url


def topic_exists(name):
    sns_client = aws_stack.create_external_boto_client("sns")
    topics = sns_client.list_topics()
    for topic in topics["Topics"]:
        topic_arn = topic["TopicArn"]
        if topic_arn.endswith(":%s" % name):
            return topic_arn


def queue_url_exists(queue_url):
    sqs_client = aws_stack.create_external_boto_client("sqs")
    queues = sqs_client.list_queues()
    return queue_url in queues["QueueUrls"]


def stream_exists(name):
    kinesis_client = aws_stack.create_external_boto_client("kinesis")
    streams = kinesis_client.list_streams()
    return name in streams["StreamNames"]


def stream_consumer_exists(stream_name, consumer_name):
    kinesis_client = aws_stack.create_external_boto_client("kinesis")
    consumers = kinesis_client.list_stream_consumers(
        StreamARN=aws_stack.kinesis_stream_arn(stream_name)
    )
    consumers = [c["ConsumerName"] for c in consumers["Consumers"]]
    return consumer_name in consumers


def ssm_param_exists(name):
    client = aws_stack.create_external_boto_client("ssm")
    params = client.describe_parameters(Filters=[{"Key": "Name", "Values": [name]}])["Parameters"]
    param = (params or [{}])[0]
    return param.get("Name") == name and param


def describe_stack_resource(stack_name, resource_logical_id):
    cloudformation = aws_stack.create_external_boto_client("cloudformation")
    response = cloudformation.describe_stack_resources(StackName=stack_name)
    for resource in response["StackResources"]:
        if resource["LogicalResourceId"] == resource_logical_id:
            return resource


def list_stack_resources(stack_name):
    cloudformation = aws_stack.create_external_boto_client("cloudformation")
    response = cloudformation.list_stack_resources(StackName=stack_name)
    return response["StackResourceSummaries"]


def get_queue_urls():
    sqs = aws_stack.create_external_boto_client("sqs")
    response = sqs.list_queues()
    return response["QueueUrls"]


def get_topic_arns():
    sqs = aws_stack.create_external_boto_client("sns")
    response = sqs.list_topics()
    return [t["TopicArn"] for t in response["Topics"]]


def expected_change_set_status():
    return "CREATE_COMPLETE"


def create_and_await_stack(**kwargs):
    cloudformation = aws_stack.create_external_boto_client("cloudformation")
    response = cloudformation.create_stack(**kwargs)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    result = await_stack_completion(kwargs["StackName"])
    return result


def update_and_await_stack(stack_name, **kwargs):
    cloudformation = aws_stack.create_external_boto_client("cloudformation")
    response = cloudformation.update_stack(StackName=stack_name, **kwargs)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return await_stack_completion(stack_name)


def delete_and_await_stack(stack_name, **kwargs):
    cloudformation = aws_stack.create_external_boto_client("cloudformation")
    response = cloudformation.delete_stack(StackName=stack_name, **kwargs)
    assert response["ResponseMetadata"]["HTTPStatusCode"] == 200
    return await_stack_completion(stack_name)


class CloudFormationTest(unittest.TestCase):
    def cleanup(self, stack_name, change_set_name=None):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        if change_set_name:
            cloudformation.delete_change_set(StackName=stack_name, ChangeSetName=change_set_name)

        resp = cloudformation.delete_stack(StackName=stack_name)
        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])

    def test_create_delete_stack(self):
        cf_client = aws_stack.create_external_boto_client("cloudformation")
        s3 = aws_stack.create_external_boto_client("s3")
        sns = aws_stack.create_external_boto_client("sns")
        sqs = aws_stack.create_external_boto_client("sqs")
        apigateway = aws_stack.create_external_boto_client("apigateway")
        template = template_preparer.template_to_json(load_file(TEST_TEMPLATE_1))

        # deploy template
        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        # assert that resources have been created
        self.assertTrue(bucket_exists("cf-test-bucket-1"))
        queue_url = queue_exists("cf-test-queue-1")
        self.assertTrue(queue_url)
        topic_arn = topic_exists("%s-test-topic-1-1" % stack_name)
        self.assertTrue(topic_arn)
        self.assertTrue(stream_exists("cf-test-stream-1"))
        self.assertTrue(stream_consumer_exists("cf-test-stream-1", "c1"))
        resource = describe_stack_resource(stack_name, "SQSQueueNoNameProperty")
        self.assertTrue(queue_exists(resource["PhysicalResourceId"]))
        self.assertTrue(ssm_param_exists("cf-test-param-1"))

        # assert that tags have been created
        expected_bucket_tags = [
            {"Key": "foobar", "Value": aws_stack.get_sqs_queue_url("cf-test-queue-1")}
        ]
        bucket_tags = s3.get_bucket_tagging(Bucket="cf-test-bucket-1")["TagSet"]
        self.assertEqual(expected_bucket_tags, bucket_tags)

        expected_topic_tags = [
            {"Key": "foo", "Value": "cf-test-bucket-1"},
            {"Key": "bar", "Value": aws_stack.s3_bucket_arn("cf-test-bucket-1")},
        ]
        topic_tags = sns.list_tags_for_resource(ResourceArn=topic_arn)["Tags"]
        self.assertEqual(expected_topic_tags, topic_tags)

        expected_queue_tags = {"key1": "value1", "key2": "value2"}
        queue_tags = sqs.list_queue_tags(QueueUrl=queue_url)
        self.assertIn("Tags", queue_tags)
        self.assertEqual(expected_queue_tags, queue_tags["Tags"])

        # assert that bucket notifications have been created
        notifications = s3.get_bucket_notification_configuration(Bucket="cf-test-bucket-1")
        self.assertIn("QueueConfigurations", notifications)
        self.assertIn("LambdaFunctionConfigurations", notifications)
        self.assertEqual(
            "aws:arn:sqs:test:testqueue",
            notifications["QueueConfigurations"][0]["QueueArn"],
        )
        self.assertEqual(["s3:ObjectDeleted:*"], notifications["QueueConfigurations"][0]["Events"])
        self.assertEqual(
            "aws:arn:lambda:test:testfunc",
            notifications["LambdaFunctionConfigurations"][0]["LambdaFunctionArn"],
        )
        self.assertEqual(
            ["s3:ObjectCreated:*"],
            notifications["LambdaFunctionConfigurations"][0]["Events"],
        )

        # assert that subscriptions have been created
        subs = sns.list_subscriptions()["Subscriptions"]
        subs = [s for s in subs if (":%s:cf-test-queue-1" % TEST_AWS_ACCOUNT_ID) in s["Endpoint"]]
        self.assertEqual(1, len(subs))
        self.assertIn(
            ":%s:%s-test-topic-1-1" % (TEST_AWS_ACCOUNT_ID, stack_name),
            subs[0]["TopicArn"],
        )
        # assert that subscription attributes are added properly
        attrs = sns.get_subscription_attributes(SubscriptionArn=subs[0]["SubscriptionArn"])[
            "Attributes"
        ]
        expected = {
            "Endpoint": subs[0]["Endpoint"],
            "Protocol": "sqs",
            "SubscriptionArn": subs[0]["SubscriptionArn"],
            "TopicArn": subs[0]["TopicArn"],
            "FilterPolicy": json.dumps({"eventType": ["created"]}),
            "PendingConfirmation": "false",
        }
        self.assertEqual(expected, attrs)

        # assert that Gateway responses have been created
        test_api_name = "test-api"
        api = [a for a in apigateway.get_rest_apis()["items"] if a["name"] == test_api_name][0]
        responses = apigateway.get_gateway_responses(restApiId=api["id"])["items"]
        self.assertEqual(2, len(responses))
        responses_types = {r["responseType"] for r in responses}
        self.assertSetEqual({"UNAUTHORIZED", "DEFAULT_5XX"}, responses_types)

        # delete the stack
        cf_client.delete_stack(StackName=stack_name)

        # assert that resources have been deleted
        self.assertFalse(bucket_exists("cf-test-bucket-1"))
        self.assertFalse(queue_exists("cf-test-queue-1"))
        self.assertFalse(topic_exists("%s-test-topic-1-1" % stack_name))
        retry(lambda: self.assertFalse(stream_exists("cf-test-stream-1")))

    def test_list_stack_events(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        response = cloudformation.describe_stack_events()
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

    def test_validate_template(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        template = template_preparer.template_to_json(load_file(TEST_VALID_TEMPLATE))
        resp = cloudformation.validate_template(TemplateBody=template)

        self.assertEqual(200, resp["ResponseMetadata"]["HTTPStatusCode"])
        self.assertIn("Parameters", resp)
        self.assertEqual(1, len(resp["Parameters"]))
        self.assertEqual("KeyExample", resp["Parameters"][0]["ParameterKey"])
        self.assertEqual(
            "The EC2 Key Pair to allow SSH access to the instance",
            resp["Parameters"][0]["Description"],
        )

    def test_validate_invalid_json_template_should_fail(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        invalid_json = '{"this is invalid JSON"="bobbins"}'

        try:
            cloudformation.validate_template(TemplateBody=invalid_json)
            self.fail("Should raise ValidationError")
        except (ClientError, ResponseParserError) as err:
            if isinstance(err, ClientError):
                self.assertEqual(400, err.response["ResponseMetadata"]["HTTPStatusCode"])
                self.assertEqual("Template Validation Error", err.response["Error"]["Message"])

    def test_list_stack_resources_returns_queue_urls(self):
        stack_name = "stack-%s" % short_uid()
        details = create_and_await_stack(
            StackName=stack_name, TemplateBody=load_file(TEST_TEMPLATE_27)
        )

        stack_summaries = list_stack_resources(stack_name)
        queue_urls = get_queue_urls()
        topic_arns = get_topic_arns()

        stack_queues = [r for r in stack_summaries if r["ResourceType"] == "AWS::SQS::Queue"]
        for resource in stack_queues:
            self.assertIn(resource["PhysicalResourceId"], queue_urls)

        stack_topics = [r for r in stack_summaries if r["ResourceType"] == "AWS::SNS::Topic"]
        for resource in stack_topics:
            self.assertIn(resource["PhysicalResourceId"], topic_arns)

        # assert that stack outputs are returned properly
        outputs = details.get("Outputs", [])
        self.assertEqual(1, len(outputs))
        self.assertEqual("T27SQSQueue-URL", outputs[0]["ExportName"])
        self.assertIn(config.DEFAULT_REGION, outputs[0]["OutputValue"])

        # clean up
        self.cleanup(stack_name)

    def test_create_change_set(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        # deploy template
        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_3)

        # create change set with the same template (no changes)
        response = cloudformation.create_change_set(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_3,
            ChangeSetName="nochanges",
        )
        self.assertIn(":%s:changeSet/nochanges/" % TEST_AWS_ACCOUNT_ID, response["Id"])
        self.assertIn(":%s:stack/" % TEST_AWS_ACCOUNT_ID, response["StackId"])

    def test_sam_template(self):
        awslambda = aws_stack.create_external_boto_client("lambda")

        # deploy template
        stack_name = "stack-%s" % short_uid()
        func_name = "test-%s" % short_uid()
        template = load_file(TEST_TEMPLATE_4) % func_name
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        # run Lambda test invocation
        result = awslambda.invoke(FunctionName=func_name)
        result = json.loads(to_str(result["Payload"].read()))
        self.assertEqual({"hello": "world"}, result)

        # delete lambda function
        awslambda.delete_function(FunctionName=func_name)

    def test_nested_stack(self):
        s3 = aws_stack.create_external_boto_client("s3")
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        # upload template to S3
        s3.create_bucket(Bucket=TEST_ARTIFACTS_BUCKET, ACL="public-read")
        s3.put_object(
            Bucket=TEST_ARTIFACTS_BUCKET,
            Key=TEST_ARTIFACTS_PATH,
            Body=load_file(TEST_TEMPLATE_5),
        )

        # deploy template
        buckets_before = len(s3.list_buckets()["Buckets"])
        stack_name = "stack-%s" % short_uid()
        param_value = short_uid()
        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_TEMPLATE_6) % (TEST_ARTIFACTS_BUCKET, TEST_ARTIFACTS_PATH),
            Parameters=[{"ParameterKey": "GlobalParam", "ParameterValue": param_value}],
        )

        # assert that nested resources have been created
        buckets_after = s3.list_buckets()["Buckets"]
        num_buckets_after = len(buckets_after)
        self.assertEqual(buckets_before + 1, num_buckets_after)
        bucket_names = [b["Name"] for b in buckets_after]
        self.assertIn("test-%s" % param_value, bucket_names)

        # delete the stack
        cloudformation.delete_stack(StackName=stack_name)

    def test_create_cfn_lambda_without_function_name(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        rs = lambda_client.list_functions()
        # Number of lambdas before of stack creation
        lambdas_before = len(rs["Functions"])

        stack_name = "stack-%s" % short_uid()
        lambda_role_name = "lambda-role-%s" % short_uid()

        template = json.loads(load_file(TEST_TEMPLATE_7))
        template["Resources"]["LambdaExecutionRole"]["Properties"]["RoleName"] = lambda_role_name
        create_and_await_stack(StackName=stack_name, TemplateBody=json.dumps(template))

        rs = lambda_client.list_functions()

        # There is 1 new lambda function
        self.assertEqual(lambdas_before + 1, len(rs["Functions"]))

        # delete the stack
        cloudformation.delete_stack(StackName=stack_name)

        rs = lambda_client.list_functions()

        # Back to what we had before
        self.assertEqual(lambdas_before, len(rs["Functions"]))

    def test_deploy_stack_change_set(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        stack_name = "stack-%s" % short_uid()
        change_set_name = "change-set-%s" % short_uid()
        bucket_name = "bucket-%s" % short_uid()

        with self.assertRaises(ClientError) as ctx:
            cloudformation.describe_stacks(StackName=stack_name)
        self.assertEqual("ValidationError", ctx.exception.response["Error"]["Code"])

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_CHANGE_SET_BODY % bucket_name,
            Parameters=[{"ParameterKey": "EnvironmentType", "ParameterValue": "stage"}],
            Capabilities=["CAPABILITY_IAM"],
            ChangeSetType="CREATE",
        )

        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        change_set_id = rs["Id"]

        rs = cloudformation.describe_change_set(StackName=stack_name, ChangeSetName=change_set_id)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(change_set_name, rs["ChangeSetName"])
        self.assertEqual(change_set_id, rs["ChangeSetId"])
        self.assertEqual(expected_change_set_status(), rs["Status"])

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
        stack = rs["Stacks"][0]
        parameters = stack["Parameters"]

        self.assertEqual(stack_name, stack["StackName"])
        self.assertEqual("EnvironmentType", parameters[0]["ParameterKey"])
        self.assertEqual("stage", parameters[0]["ParameterValue"])

        self.assertTrue(bucket_exists(bucket_name))

        # clean up
        self.cleanup(stack_name, change_set_name)

    def test_deploy_stack_with_iam_role(self):
        stack_name = "stack-%s" % short_uid()
        change_set_name = "change-set-%s" % short_uid()
        role_name = "role-%s" % short_uid()

        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        iam_client = aws_stack.create_external_boto_client("iam")
        roles_before = iam_client.list_roles()["Roles"]

        with self.assertRaises(ClientError) as ctx:
            cloudformation.describe_stacks(StackName=stack_name)
        self.assertEqual("ValidationError", ctx.exception.response["Error"]["Code"])

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_1) % role_name,
            ChangeSetType="CREATE",
        )

        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        change_set_id = rs["Id"]

        rs = cloudformation.describe_change_set(StackName=stack_name, ChangeSetName=change_set_id)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(change_set_name, rs["ChangeSetName"])
        self.assertEqual(change_set_id, rs["ChangeSetId"])
        self.assertEqual(expected_change_set_status(), rs["Status"])

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
        stack = rs["Stacks"][0]
        self.assertEqual(stack_name, stack["StackName"])

        rs = iam_client.list_roles()
        self.assertEqual(len(roles_before) + 1, len(rs["Roles"]))
        self.assertEqual(role_name, rs["Roles"][-1]["RoleName"])

        rs = iam_client.list_role_policies(RoleName=role_name)
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=rs["PolicyNames"][0])

        # clean up
        self.cleanup(stack_name, change_set_name)
        rs = iam_client.list_roles(PathPrefix=role_name)
        self.assertEqual(0, len(rs["Roles"]))

    def test_deploy_stack_with_sns_topic(self):
        stack_name = "stack-%s" % short_uid()
        change_set_name = "change-set-%s" % short_uid()

        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_2),
            Parameters=[
                {"ParameterKey": "CompanyName", "ParameterValue": "MyCompany"},
                {"ParameterKey": "MyEmail1", "ParameterValue": "my@email.com"},
            ],
            ChangeSetType="CREATE",
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
        stack = rs["Stacks"][0]
        self.assertEqual(stack_name, stack["StackName"])
        outputs = stack["Outputs"]
        self.assertEqual(3, len(outputs))

        topic_arn = None
        for op in outputs:
            if op["OutputKey"] == "MyTopic":
                topic_arn = op["OutputValue"]

        sns_client = aws_stack.create_external_boto_client("sns")
        rs = sns_client.list_topics()

        # Topic resource created
        topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
        self.assertEqual(1, len(topics))

        # clean up
        self.cleanup(stack_name, change_set_name)
        # assert topic resource removed
        rs = sns_client.list_topics()
        topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
        self.assertEqual(0, len(topics))

    def test_deploy_stack_with_dynamodb_table(self):
        stack_name = "stack-%s" % short_uid()
        change_set_name = "change-set-%s" % short_uid()
        env = "Staging"
        ddb_table_name_prefix = "ddb-table-%s" % short_uid()
        ddb_table_name = "{}-{}".format(ddb_table_name_prefix, env)

        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_3),
            Parameters=[
                {"ParameterKey": "tableName", "ParameterValue": ddb_table_name_prefix},
                {"ParameterKey": "env", "ParameterValue": env},
            ],
            ChangeSetType="CREATE",
        )
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        change_set_id = rs["Id"]

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        await_stack_completion(stack_name)
        rs = cloudformation.describe_stacks(StackName=stack_name)

        stacks = [stack for stack in rs["Stacks"] if stack["StackName"] == stack_name]
        self.assertEqual(1, len(stacks))
        self.assertEqual(change_set_id, stacks[0]["ChangeSetId"])

        outputs = {output["OutputKey"]: output["OutputValue"] for output in stacks[0]["Outputs"]}
        self.assertIn("Arn", outputs)

        expected_dynamodb_table_arn = "arn:aws:dynamodb:{}:{}:table/{}".format(
            aws_stack.get_region(),
            TEST_AWS_ACCOUNT_ID,
            ddb_table_name,
        )
        self.assertEqual(expected_dynamodb_table_arn, outputs["Arn"])

        self.assertIn("Name", outputs)
        self.assertEqual(ddb_table_name, outputs["Name"])

        ddb_client = aws_stack.create_external_boto_client("dynamodb")
        rs = ddb_client.list_tables()
        self.assertIn(ddb_table_name, rs["TableNames"])

        # clean up
        self.cleanup(stack_name, change_set_name)
        rs = ddb_client.list_tables()
        self.assertNotIn(ddb_table_name, rs["TableNames"])

    def test_deploy_stack_with_iam_nested_policy(self):
        stack_name = "stack-%s" % short_uid()
        change_set_name = "change-set-%s" % short_uid()

        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_4),
            ChangeSetType="CREATE",
        )

        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        change_set_id = rs["Id"]

        rs = cloudformation.describe_change_set(StackName=stack_name, ChangeSetName=change_set_id)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(change_set_id, rs["ChangeSetId"])
        self.assertEqual(expected_change_set_status(), rs["Status"])

        iam_client = aws_stack.create_external_boto_client("iam")
        rs = iam_client.list_roles()
        number_of_roles = len(rs["Roles"])

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        await_stack_completion(stack_name)

        rs = iam_client.list_roles()
        # 1 role was created
        self.assertEqual(number_of_roles + 1, len(rs["Roles"]))

        # clean up
        self.cleanup(stack_name, change_set_name)
        # assert role was removed
        rs = iam_client.list_roles()
        self.assertEqual(number_of_roles, len(rs["Roles"]))

    def test_cfn_handle_s3_bucket_resources(self):
        stack_name = "stack-%s" % short_uid()
        bucket_name = "s3-bucket-%s" % short_uid()

        TEST_TEMPLATE_8["Resources"]["S3Bucket"]["Properties"]["BucketName"] = bucket_name
        template_body = json.dumps(TEST_TEMPLATE_8)

        self.assertFalse(bucket_exists(bucket_name))

        s3 = aws_stack.create_external_boto_client("s3")

        deploy_cf_stack(stack_name=stack_name, template_body=template_body)

        self.assertTrue(bucket_exists(bucket_name))
        rs = s3.get_bucket_policy(Bucket=bucket_name)
        self.assertIn("Policy", rs)
        policy_doc = TEST_TEMPLATE_8["Resources"]["S3BucketPolicy"]["Properties"]["PolicyDocument"]
        self.assertEqual(policy_doc, json.loads(rs["Policy"]))

        # clean up, assert resources deleted
        self.cleanup(stack_name)

        self.assertFalse(bucket_exists(bucket_name))
        with self.assertRaises(ClientError) as ctx:
            s3.get_bucket_policy(Bucket=bucket_name)
        self.assertEqual("NoSuchBucket", ctx.exception.response["Error"]["Code"])

        # recreate stack
        create_and_await_stack(StackName=stack_name, TemplateBody=template_body)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_log_group_resource(self):
        stack_name = "stack-%s" % short_uid()
        log_group_prefix = "/aws/lambda/AWS_DUB_LAM_10000000"

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_9)

        logs_client = aws_stack.create_external_boto_client("logs")
        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)

        self.assertEqual(1, len(rs["logGroups"]))
        self.assertEqual(
            "/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev",
            rs["logGroups"][0]["logGroupName"],
        )

        # clean up and assert deletion
        self.cleanup(stack_name)
        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
        self.assertEqual(0, len(rs["logGroups"]))

    def test_cfn_handle_elasticsearch_domain(self):
        stack_name = "stack-%s" % short_uid()
        domain_name = "es-%s" % short_uid()

        es_client = aws_stack.create_external_boto_client("es")

        details = create_and_await_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_10,
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
        )
        outputs = details.get("Outputs", [])
        self.assertEqual(4, len(outputs))

        rs = es_client.describe_elasticsearch_domain(DomainName=domain_name)
        status = rs["DomainStatus"]
        self.assertEqual(domain_name, status["DomainName"])

        tags = es_client.list_tags(ARN=status["ARN"])["TagList"]
        self.assertEqual([{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}], tags)

        for o in outputs:
            if o["OutputKey"] in ["MyElasticsearchArn", "MyElasticsearchDomainArn"]:
                self.assertEqual(o["OutputValue"], status["ARN"])
            elif o["OutputKey"] == "MyElasticsearchDomainEndpoint":
                self.assertEqual(o["OutputValue"], status["Endpoint"])
            elif o["OutputKey"] == "MyElasticsearchRef":
                self.assertEqual(o["OutputValue"], status["DomainName"])
            else:
                self.fail("Unexpected output: %s" % o)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_secretsmanager_secret(self):
        stack_name = "stack-%s" % short_uid()
        secret_name = "secret-%s" % short_uid()

        params = [{"ParameterKey": "SecretName", "ParameterValue": secret_name}]
        create_and_await_stack(
            StackName=stack_name, TemplateBody=TEST_TEMPLATE_11, Parameters=params
        )

        secretsmanager_client = aws_stack.create_external_boto_client("secretsmanager")

        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
        self.assertEqual(secret_name, rs["Name"])
        self.assertNotIn("DeletedDate", rs)

        # clean up
        self.cleanup(stack_name)
        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
        self.assertIn("DeletedDate", rs)

    def test_cfn_handle_kinesis_firehose_resources(self):
        stack_name = "stack-%s" % short_uid()
        kinesis_stream_name = "kinesis-stream-%s" % short_uid()
        firehose_role_name = "firehose-role-%s" % short_uid()
        firehose_stream_name = "firehose-stream-%s" % short_uid()

        details = create_and_await_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_12 % firehose_role_name,
            Parameters=[
                {
                    "ParameterKey": "KinesisStreamName",
                    "ParameterValue": kinesis_stream_name,
                },
                {
                    "ParameterKey": "DeliveryStreamName",
                    "ParameterValue": firehose_stream_name,
                },
            ],
        )

        outputs = details.get("Outputs", [])
        self.assertEqual(1, len(outputs))

        kinesis_client = aws_stack.create_external_boto_client("kinesis")
        firehose_client = aws_stack.create_external_boto_client("firehose")

        rs = firehose_client.describe_delivery_stream(DeliveryStreamName=firehose_stream_name)
        self.assertEqual(
            outputs[0]["OutputValue"],
            rs["DeliveryStreamDescription"]["DeliveryStreamARN"],
        )
        self.assertEqual(
            firehose_stream_name, rs["DeliveryStreamDescription"]["DeliveryStreamName"]
        )

        rs = kinesis_client.describe_stream(StreamName=kinesis_stream_name)
        self.assertEqual(kinesis_stream_name, rs["StreamDescription"]["StreamName"])

        # clean up
        self.cleanup(stack_name)
        time.sleep(1)
        rs = kinesis_client.list_streams()
        self.assertNotIn(kinesis_stream_name, rs["StreamNames"])
        rs = firehose_client.list_delivery_streams()
        self.assertNotIn(firehose_stream_name, rs["DeliveryStreamNames"])

    def test_cfn_handle_iam_role_resource(self):
        stack_name = "stack-%s" % short_uid()
        role_name = "role-%s" % short_uid()
        policy_name = "policy-%s" % short_uid()
        role_path_prefix = "/role-prefix-%s/" % short_uid()

        template_body = TEST_TEMPLATE_13 % (role_name, role_path_prefix, policy_name)
        deploy_cf_stack(stack_name=stack_name, template_body=template_body)

        iam = aws_stack.create_external_boto_client("iam")
        rs = iam.list_roles(PathPrefix=role_path_prefix)

        self.assertEqual(1, len(rs["Roles"]))
        role = rs["Roles"][0]
        self.assertEqual(role_name, role["RoleName"])

        result = iam.get_policy(PolicyArn=aws_stack.policy_arn(policy_name))
        self.assertEqual(policy_name, result["Policy"]["PolicyName"])

        # clean up
        self.cleanup(stack_name)
        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(0, len(rs["Roles"]))

    def test_cfn_handle_iam_role_resource_no_role_name(self):
        iam = aws_stack.create_external_boto_client("iam")

        stack_name = "stack-%s" % short_uid()
        role_path_prefix = "/role-prefix-%s/" % short_uid()

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_14 % role_path_prefix)

        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(1, len(rs["Roles"]))

        # clean up
        self.cleanup(stack_name)
        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(0, len(rs["Roles"]))

    def test_describe_template(self):
        s3 = aws_stack.create_external_boto_client("s3")
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        bucket_name = "b-%s" % short_uid()
        template_body = TEST_TEMPLATE_12 % "test-firehose-role-name"
        s3.create_bucket(Bucket=bucket_name, ACL="public-read")
        s3.put_object(Bucket=bucket_name, Key="template.yml", Body=template_body)

        template_url = "%s/%s/template.yml" % (config.get_edge_url(), bucket_name)

        params = [
            {"ParameterKey": "KinesisStreamName"},
            {"ParameterKey": "DeliveryStreamName"},
        ]
        # get summary by template URL
        result = cloudformation.get_template_summary(TemplateURL=template_url)
        self.assertEqual(params, result.get("Parameters"))
        self.assertIn("AWS::S3::Bucket", result["ResourceTypes"])
        self.assertTrue(result.get("ResourceIdentifierSummaries"))
        # get summary by template body
        result = cloudformation.get_template_summary(TemplateBody=template_body)
        self.assertEqual(params, result.get("Parameters"))
        self.assertIn("AWS::Kinesis::Stream", result["ResourceTypes"])
        self.assertTrue(result.get("ResourceIdentifierSummaries"))

    def test_stack_imports(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        result = cloudformation.list_imports(ExportName="_unknown_")
        self.assertEqual(200, result["ResponseMetadata"]["HTTPStatusCode"])
        self.assertEqual(result["Imports"], [])  # TODO: create test with actual import values!

        queue_name1 = "q-%s" % short_uid()
        queue_name2 = "q-%s" % short_uid()
        template1 = TEST_TEMPLATE_26_1 % queue_name1
        template2 = TEST_TEMPLATE_26_2 % queue_name2
        stack_name1 = "stack-%s" % short_uid()
        deploy_cf_stack(stack_name=stack_name1, template_body=template1)
        stack_name2 = "stack-%s" % short_uid()
        deploy_cf_stack(stack_name=stack_name2, template_body=template2)

        sqs = aws_stack.create_external_boto_client("sqs")
        queue_url1 = sqs.get_queue_url(QueueName=queue_name1)["QueueUrl"]
        queue_url2 = sqs.get_queue_url(QueueName=queue_name2)["QueueUrl"]

        queues = sqs.list_queues().get("QueueUrls", [])
        self.assertIn(queue_url1, queues)
        self.assertIn(queue_url2, queues)

        outputs = cloudformation.describe_stacks(StackName=stack_name2)["Stacks"][0]["Outputs"]
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl1"][
            0
        ]
        self.assertEqual(aws_stack.sqs_queue_arn(queue_url1), output)
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl2"][
            0
        ]
        self.assertEqual(queue_url2, output)

    def test_cfn_conditional_deployment(self):
        s3 = aws_stack.create_external_boto_client("s3")

        bucket_id = short_uid()
        template = TEST_TEMPLATE_19.format(id=bucket_id)
        stack_name = "stack-%s" % short_uid()
        deploy_cf_stack(stack_name=stack_name, template_body=template)

        buckets = s3.list_buckets()["Buckets"]
        dev_bucket = "cf-dev-%s" % bucket_id
        prd_bucket = "cf-prd-%s" % bucket_id
        dev_bucket = [b for b in buckets if b["Name"] == dev_bucket]
        prd_bucket = [b for b in buckets if b["Name"] == prd_bucket]

        self.assertFalse(prd_bucket)
        self.assertTrue(dev_bucket)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_sqs_resource(self):
        stack_name = "stack-%s" % short_uid()
        fifo_queue = "queue-%s.fifo" % short_uid()

        sqs = aws_stack.create_external_boto_client("sqs")

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_15 % fifo_queue)

        rs = sqs.get_queue_url(QueueName=fifo_queue)
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])

        queue_url = rs["QueueUrl"]

        rs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        attributes = rs["Attributes"]
        self.assertIn("ContentBasedDeduplication", attributes)
        self.assertIn("FifoQueue", attributes)
        self.assertEqual("false", attributes["ContentBasedDeduplication"])
        self.assertEqual("true", attributes["FifoQueue"])

        # clean up
        self.cleanup(stack_name)
        with self.assertRaises(ClientError) as ctx:
            sqs.get_queue_url(QueueName=fifo_queue)
        self.assertEqual(
            "AWS.SimpleQueueService.NonExistentQueue",
            ctx.exception.response["Error"]["Code"],
        )

    def test_cfn_handle_events_rule(self):
        stack_name = "stack-%s" % short_uid()
        bucket_name = "target-%s" % short_uid()
        rule_prefix = "s3-rule-%s" % short_uid()
        rule_name = "%s-%s" % (rule_prefix, short_uid())

        events = aws_stack.create_external_boto_client("events")

        deploy_cf_stack(
            stack_name=stack_name,
            template_body=TEST_TEMPLATE_16 % (bucket_name, rule_name),
        )

        rs = events.list_rules(NamePrefix=rule_prefix)
        self.assertIn(rule_name, [rule["Name"] for rule in rs["Rules"]])

        target_arn = aws_stack.s3_bucket_arn(bucket_name)
        rs = events.list_targets_by_rule(Rule=rule_name)
        self.assertIn(target_arn, [target["Arn"] for target in rs["Targets"]])

        # clean up
        self.cleanup(stack_name)
        rs = events.list_rules(NamePrefix=rule_prefix)
        self.assertNotIn(rule_name, [rule["Name"] for rule in rs["Rules"]])

    def test_cfn_handle_events_rule_without_name(self):
        events = aws_stack.create_external_boto_client("events")

        rs = events.list_rules()
        rule_names = [rule["Name"] for rule in rs["Rules"]]

        stack_name = "stack-%s" % short_uid()
        deploy_cf_stack(
            stack_name=stack_name,
            template_body=TEST_TEMPLATE_18 % aws_stack.role_arn("sfn_role"),
        )

        rs = events.list_rules()
        new_rules = [rule for rule in rs["Rules"] if rule["Name"] not in rule_names]
        self.assertEqual(1, len(new_rules))
        rule = new_rules[0]

        self.assertEqual("cron(0/1 * * * ? *)", rule["ScheduleExpression"])

        # clean up
        self.cleanup(stack_name)
        time.sleep(1)
        rs = events.list_rules()
        self.assertNotIn(rule["Name"], [r["Name"] for r in rs["Rules"]])

    def test_cfn_handle_s3_notification_configuration(self):
        stack_name = "stack-%s" % short_uid()
        bucket_name = "target-%s" % short_uid()
        queue_name = "queue-%s" % short_uid()
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        s3 = aws_stack.create_external_boto_client("s3")

        deploy_cf_stack(
            stack_name=stack_name,
            template_body=TEST_TEMPLATE_17 % (queue_name, bucket_name, queue_arn),
        )

        rs = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        self.assertIn("QueueConfigurations", rs)
        self.assertEqual(1, len(rs["QueueConfigurations"]))
        self.assertEqual(queue_arn, rs["QueueConfigurations"][0]["QueueArn"])

        # clean up
        self.cleanup(stack_name)
        rs = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        self.assertNotIn("QueueConfigurations", rs)

    def test_cfn_lambda_function_with_iam_role(self):
        stack_name = "stack-%s" % short_uid()
        role_name = "lambda-ex"

        iam = aws_stack.create_external_boto_client("iam")

        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {'
            '"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}',
        )
        self.assertEqual(role_name, response["Role"]["RoleName"])

        response = iam.get_role(RoleName=role_name)
        self.assertEqual(role_name, response["Role"]["RoleName"])

        role_arn = response["Role"]["Arn"]
        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_20 % role_arn,
        )

        # clean up
        self.cleanup(stack_name)
        iam.delete_role(RoleName=role_name)

    def test_cfn_handle_serverless_api_resource(self):
        stack_name = "stack-%s" % short_uid()

        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_22)

        res = cloudformation.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
        rest_api_ids = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]
        lambda_func_names = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::Lambda::Function"
        ]

        self.assertEqual(1, len(rest_api_ids))
        self.assertEqual(1, len(lambda_func_names))

        apigw_client = aws_stack.create_external_boto_client("apigateway")
        rs = apigw_client.get_resources(restApiId=rest_api_ids[0])
        self.assertEqual(1, len(rs["items"]))
        resource = rs["items"][0]

        uri = resource["resourceMethods"]["GET"]["methodIntegration"]["uri"]
        lambda_arn = aws_stack.lambda_function_arn(lambda_func_names[0])
        self.assertIn(lambda_arn, uri)

        # clean up
        self.cleanup(stack_name)

    def test_delete_stack(self):
        domain_name = "es-%s" % short_uid()
        stack_name1 = "s1-%s" % short_uid()
        stack_name2 = "s2-%s" % short_uid()

        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        create_and_await_stack(
            StackName=stack_name1,
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
        )

        create_and_await_stack(
            StackName=stack_name2,
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
        )

        # clean up
        cloudformation.delete_stack(StackName=stack_name1)
        cloudformation.delete_stack(StackName=stack_name2)

    def test_cfn_with_on_demand_dynamodb_resource(self):
        stack_name = "test-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=load_file(TEST_TEMPLATE_21))
        # clean up
        self.cleanup(stack_name)

    def test_update_lambda_function(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        bucket_name = "bucket-{}".format(short_uid())
        key_name = "lambda-package"
        role_name = "role-{}".format(short_uid())
        function_name = "func-{}".format(short_uid())
        package_path = os.path.join(THIS_FOLDER, "lambdas", "lambda_echo.js")

        stack_name = "stack-{}".format(short_uid())

        template = json.loads(load_file(TEST_UPDATE_LAMBDA_FUNCTION_TEMPLATE))
        template["Resources"]["PullMarketsRole"]["Properties"]["RoleName"] = role_name

        props = template["Resources"]["SomeNameFunction"]["Properties"]
        props["Code"]["S3Bucket"] = bucket_name
        props["Code"]["S3Key"] = key_name
        props["FunctionName"] = function_name

        s3 = aws_stack.create_external_boto_client("s3")
        s3.create_bucket(Bucket=bucket_name, ACL="public-read")
        s3.put_object(
            Bucket=bucket_name,
            Key=key_name,
            Body=create_zip_file(package_path, get_content=True),
        )

        create_and_await_stack(StackName=stack_name, TemplateBody=json.dumps(template))

        props.update({"Environment": {"Variables": {"AWS_NODEJS_CONNECTION_REUSE_ENABLED": 1}}})
        rs = cloudformation.update_stack(StackName=stack_name, TemplateBody=json.dumps(template))
        self.assertEqual(200, rs["ResponseMetadata"]["HTTPStatusCode"])
        await_stack_completion(stack_name)

        rs = lambda_client.get_function(FunctionName=function_name)
        self.assertEqual(function_name, rs["Configuration"]["FunctionName"])
        self.assertIn(
            "AWS_NODEJS_CONNECTION_REUSE_ENABLED",
            rs["Configuration"]["Environment"]["Variables"],
        )

        # clean up
        self.cleanup(stack_name)

    def test_cfn_deploy_apigateway_integration(self):
        stack_name = "stack-%s" % short_uid()
        bucket_name = "hofund-local-deployment"
        key_name = "serverless/hofund/local/1599143878432/authorizer.zip"
        package_path = os.path.join(THIS_FOLDER, "lambdas", "lambda_echo.js")

        template = template_preparer.template_to_json(load_file(APIGW_INTEGRATION_TEMPLATE))

        s3 = aws_stack.create_external_boto_client("s3")
        s3.create_bucket(Bucket=bucket_name, ACL="public-read")
        s3.put_object(
            Bucket=bucket_name,
            Key=key_name,
            Body=create_zip_file(package_path, get_content=True),
        )

        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        apigw_client = aws_stack.create_external_boto_client("apigateway")

        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        stack_resources = cloudformation.list_stack_resources(StackName=stack_name)[
            "StackResourceSummaries"
        ]
        rest_apis = [
            res for res in stack_resources if res["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]

        rs = apigw_client.get_rest_api(restApiId=rest_apis[0]["PhysicalResourceId"])
        self.assertEqual("ApiGatewayRestApi", rs["name"])

        # clean up
        self.cleanup(stack_name)

    def test_globalindex_read_write_provisioned_throughput_dynamodb_table(self):
        ddb_client = aws_stack.create_external_boto_client("dynamodb")
        stack_name = "test_dynamodb"

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_3),
            Parameters=[
                {"ParameterKey": "tableName", "ParameterValue": "dynamodb"},
                {"ParameterKey": "env", "ParameterValue": "test"},
            ],
        )

        response = ddb_client.describe_table(TableName="dynamodb-test")

        if response["Table"]["ProvisionedThroughput"]:
            throughput = response["Table"]["ProvisionedThroughput"]
            self.assertTrue(isinstance(throughput["ReadCapacityUnits"], int))
            self.assertTrue(isinstance(throughput["WriteCapacityUnits"], int))

        for global_index in response["Table"]["GlobalSecondaryIndexes"]:
            index_provisioned = global_index["ProvisionedThroughput"]
            test_read_capacity = index_provisioned["ReadCapacityUnits"]
            test_write_capacity = index_provisioned["WriteCapacityUnits"]
            self.assertTrue(isinstance(test_read_capacity, int))
            self.assertTrue(isinstance(test_write_capacity, int))

        # clean up
        self.cleanup(stack_name)

    def test_delete_stack_across_regions(self):
        domain_name = "es-%s" % short_uid()
        stack_name = "stack-%s" % short_uid()

        s3 = aws_stack.create_external_boto_client("s3", region_name="eu-central-1")

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{"ParameterKey": "DomainName", "ParameterValue": domain_name}],
        )

        # assert bucket created
        bucket_name = TEST_TEMPLATE_3.split("BucketName:")[1].split("\n")[0].strip()
        response = s3.head_bucket(Bucket=bucket_name)
        self.assertEqual(200, response["ResponseMetadata"]["HTTPStatusCode"])

        # clean up
        self.cleanup(stack_name)
        with self.assertRaises(Exception):
            s3.head_bucket(Bucket=bucket_name)

    def test_update_stack_with_same_template(self):
        stack_name = "stack-%s" % short_uid()
        template_data = load_file(SQS_TEMPLATE)
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        params = {"StackName": stack_name, "TemplateBody": template_data}
        create_and_await_stack(**params)

        with self.assertRaises(Exception) as ctx:
            cloudformation.update_stack(**params)
            waiter = cloudformation.get_waiter("stack_update_complete")
            waiter.wait(StackName=stack_name)

        error_message = str(ctx.exception)
        self.assertIn("UpdateStack", error_message)
        self.assertIn("No updates are to be performed.", error_message)

        # clean up
        self.cleanup(stack_name)

    def test_cdk_template(self):
        stack_name = "stack-%s" % short_uid()
        bucket = "bucket-%s" % short_uid()
        key = "key-%s" % short_uid()
        path = os.path.join(THIS_FOLDER, "templates", "asset")

        s3_client = aws_stack.create_external_boto_client("s3")
        s3_client.create_bucket(Bucket=bucket)
        s3_client.put_object(Bucket=bucket, Key=key, Body=create_zip_file(path, get_content=True))

        template = load_file(os.path.join(THIS_FOLDER, "templates", "cdktemplate.json"))

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[
                {
                    "ParameterKey": "AssetParameters1S3BucketEE4ED9A8",
                    "ParameterValue": bucket,
                },
                {
                    "ParameterKey": "AssetParameters1S3VersionKeyE160C88A",
                    "ParameterValue": key,
                },
            ],
        )

        lambda_client = aws_stack.create_external_boto_client("lambda")

        resp = lambda_client.list_functions()
        functions = [func for func in resp["Functions"] if stack_name in func["FunctionName"]]

        self.assertEqual(2, len(functions))
        self.assertEqual(
            1,
            len([func for func in functions if func["Handler"] == "index.createUserHandler"]),
        )
        self.assertEqual(
            1,
            len([func for func in functions if func["Handler"] == "index.authenticateUserHandler"]),
        )

        # clean up
        self.cleanup(stack_name)

    def test_cfn_template_with_short_form_fn_sub(self):
        stack_name = "stack-%s" % short_uid()
        environment = "env-%s" % short_uid()
        iam_client = aws_stack.create_external_boto_client("iam")

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_TEMPLATE_23),
            Parameters=[
                {"ParameterKey": "Environment", "ParameterValue": environment},
                {"ParameterKey": "ApiKey", "ParameterValue": "12345"},
            ],
        )

        # 2 roles created successfully
        rs = iam_client.list_roles()
        roles = [role for role in rs["Roles"] if stack_name in role["RoleName"]]

        self.assertEqual(2, len(roles))

        sfn_client = aws_stack.create_external_boto_client("stepfunctions")
        state_machines_after = sfn_client.list_state_machines()["stateMachines"]

        state_machines = [
            sm for sm in state_machines_after if "{}-StateMachine-".format(stack_name) in sm["name"]
        ]

        self.assertEqual(1, len(state_machines))
        rs = sfn_client.describe_state_machine(stateMachineArn=state_machines[0]["stateMachineArn"])

        definition = json.loads(rs["definition"].replace("\n", ""))
        payload = definition["States"]["time-series-update"]["Parameters"]["Payload"]
        self.assertEqual({"key": "12345"}, payload)

        # clean up
        self.cleanup(stack_name)

    def test_sub_in_lambda_function_name(self):
        stack_name = "stack-%s" % short_uid()
        environment = "env-%s" % short_uid()
        bucket = "bucket-%s" % short_uid()
        key = "key-%s" % short_uid()

        package_path = os.path.join(THIS_FOLDER, "lambdas", "lambda_echo.js")

        s3 = aws_stack.create_external_boto_client("s3")
        s3.create_bucket(Bucket=bucket, ACL="public-read")
        s3.put_object(Bucket=bucket, Key=key, Body=create_zip_file(package_path, get_content=True))
        time.sleep(1)

        template = load_file(TEST_TEMPLATE_24) % (bucket, key, bucket, key)

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "Environment", "ParameterValue": environment}],
        )

        lambda_client = aws_stack.create_external_boto_client("lambda")
        functions = lambda_client.list_functions()["Functions"]

        # assert Lambda functions created with expected name and ARN
        func_prefix = "test-{}-connectionHandler".format(environment)
        functions = [func for func in functions if func["FunctionName"].startswith(func_prefix)]
        self.assertEqual(2, len(functions))
        func1 = [f for f in functions if f["FunctionName"].endswith("connectionHandler1")][0]
        func2 = [f for f in functions if f["FunctionName"].endswith("connectionHandler2")][0]
        self.assertTrue(func1["FunctionArn"].endswith(func1["FunctionName"]))
        self.assertTrue(func2["FunctionArn"].endswith(func2["FunctionName"]))

        # assert buckets which reference Lambda names have been created
        s3_client = aws_stack.create_external_boto_client("s3")
        buckets = s3_client.list_buckets()["Buckets"]
        buckets = [b for b in buckets if b["Name"].startswith(func_prefix.lower())]
        # assert buckets are created correctly
        self.assertEqual(2, len(functions))
        tags1 = s3_client.get_bucket_tagging(Bucket=buckets[0]["Name"])
        tags2 = s3_client.get_bucket_tagging(Bucket=buckets[1]["Name"])
        # assert correct tags - they reference the function names and should equal the bucket names (lower case)
        self.assertEqual(buckets[0]["Name"], tags1["TagSet"][0]["Value"].lower())
        self.assertEqual(buckets[1]["Name"], tags2["TagSet"][0]["Value"].lower())

        # assert additional resources are present
        rg_client = aws_stack.create_external_boto_client("resource-groups")
        rg_name = "cf-rg-6427"
        groups = rg_client.list_groups().get("Groups", [])
        self.assertTrue([g for g in groups if g["Name"] == rg_name])

        # clean up
        self.cleanup(stack_name)

    def test_lambda_dependency(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        stack_name = "stack-%s" % short_uid()

        template = load_file(TEST_TEMPLATE_25)

        details = deploy_cf_stack(stack_name, template_body=template)

        # assert Lambda function created properly
        resp = lambda_client.list_functions()
        func_name = "test-forward-sns"
        functions = [func for func in resp["Functions"] if func["FunctionName"] == func_name]
        self.assertEqual(1, len(functions))

        # assert that stack outputs are returned properly
        outputs = details.get("Outputs", [])
        self.assertEqual(1, len(outputs))
        self.assertEqual("FuncArnExportName123", outputs[0]["ExportName"])

        # clean up
        self.cleanup(stack_name)

    def test_functions_in_output_export_name(self):
        stack_name = "stack-%s" % short_uid()
        environment = "env-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "template26.yaml"))
        cfn = aws_stack.create_external_boto_client("cloudformation")
        sns = aws_stack.create_external_boto_client("sns")

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "Environment", "ParameterValue": environment}],
        )

        resp = cfn.describe_stacks(StackName=stack_name)
        stack_outputs = [
            stack["Outputs"] for stack in resp["Stacks"] if stack["StackName"] == stack_name
        ]
        self.assertEqual(1, len(stack_outputs))

        outputs = {
            o["OutputKey"]: {"value": o["OutputValue"], "export": o["ExportName"]}
            for o in stack_outputs[0]
        }

        self.assertIn("VpcId", outputs)
        self.assertEqual("{}-vpc-id".format(environment), outputs["VpcId"].get("export"))

        topic_arn = aws_stack.sns_topic_arn("{}-slack-sns-topic".format(environment))
        self.assertIn("TopicArn", outputs)
        self.assertEqual(topic_arn, outputs["TopicArn"].get("export"))

        # clean up
        self.cleanup(stack_name)
        topic_arns = [t["TopicArn"] for t in sns.list_topics()["Topics"]]
        self.assertNotIn(topic_arn, topic_arns)

    def test_deploy_stack_with_kms(self):
        stack_name = "stack-%s" % short_uid()
        environment = "env-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "cdk_template_with_kms.json"))
        cfn = aws_stack.create_external_boto_client("cloudformation")

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "Environment", "ParameterValue": environment}],
        )

        resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
        kmskeys = [res for res in resources if res["ResourceType"] == "AWS::KMS::Key"]

        self.assertEqual(1, len(kmskeys))
        self.assertEqual("kmskeystack8A5DBE89", kmskeys[0]["LogicalResourceId"])
        key_id = kmskeys[0]["PhysicalResourceId"]

        self.cleanup(stack_name)

        kms = aws_stack.create_external_boto_client("kms")
        resp = kms.describe_key(KeyId=key_id)["KeyMetadata"]
        self.assertEqual("PendingDeletion", resp["KeyState"])

    def test_deploy_stack_with_sub_select_and_sub_getaz(self):
        stack_name = "stack-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "template28.yaml"))
        cfn_client = aws_stack.create_external_boto_client("cloudformation")
        sns_client = aws_stack.create_external_boto_client("sns")
        cw_client = aws_stack.create_external_boto_client("cloudwatch")

        # list resources before stack deployment
        metric_alarms = cw_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms = cw_client.describe_alarms().get("CompositeAlarms", [])

        # deploy stack
        create_and_await_stack(StackName=stack_name, TemplateBody=template)
        exports = cfn_client.list_exports()["Exports"]

        subnets = [export for export in exports if export["Name"] == "public-sn-a"]
        instances = [export for export in exports if export["Name"] == "RegmonEc2InstanceId"]

        self.assertEqual(1, len(subnets))
        self.assertEqual(1, len(instances))

        subnet_id = subnets[0]["Value"]
        instance_id = instances[0]["Value"]

        ec2_client = aws_stack.create_external_boto_client("ec2")
        resp = ec2_client.describe_subnets(SubnetIds=[subnet_id])
        self.assertEqual(1, len(resp["Subnets"]))

        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        self.assertEqual(1, len(resp["Reservations"][0]["Instances"]))

        # assert creation of further resources
        resp = sns_client.list_topics()
        topic_arns = [tp["TopicArn"] for tp in resp["Topics"]]
        self.assertIn(aws_stack.sns_topic_arn("companyname-slack-topic"), topic_arns)
        metric_alarms_after = cw_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms_after = cw_client.describe_alarms().get("CompositeAlarms", [])
        self.assertEqual(len(metric_alarms) + 1, len(metric_alarms_after))
        self.assertEqual(len(composite_alarms) + 1, len(composite_alarms_after))

        iam_client = aws_stack.create_external_boto_client("iam")
        profiles = iam_client.list_instance_profiles().get("InstanceProfiles", [])
        assert len(profiles) > 0
        profile = profiles[0]
        assert len(profile["Roles"]) > 0

        # clean up
        self.cleanup(stack_name)

    def test_cfn_update_ec2_instance_type(self):
        stack_name = "stack-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "template30.yaml"))

        cfn = aws_stack.create_external_boto_client("cloudformation")
        if cfn.meta.region_name not in [
            "ap-northeast-1",
            "eu-central-1",
            "eu-south-1",
            "eu-west-1",
            "eu-west-2",
            "us-east-1",
        ]:
            pytest.skip()
        ec2_client = aws_stack.create_external_boto_client("ec2")

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "KeyName", "ParameterValue": "testkey"}],
        )

        def get_instance_id():
            resources = cfn.list_stack_resources(StackName=stack_name)["StackResourceSummaries"]
            instances = [res for res in resources if res["ResourceType"] == "AWS::EC2::Instance"]
            self.assertEqual(1, len(instances))
            return instances[0]["PhysicalResourceId"]

        instance_id = get_instance_id()
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        self.assertEqual(1, len(resp["Reservations"][0]["Instances"]))
        self.assertEqual("t2.nano", resp["Reservations"][0]["Instances"][0]["InstanceType"])

        cfn.update_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "InstanceType", "ParameterValue": "t2.medium"}],
        )
        await_stack_completion(stack_name, statuses="UPDATE_COMPLETE")

        instance_id = get_instance_id()  # get ID of updated instance (may have changed!)
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp["Reservations"]
        self.assertEqual(1, len(reservations))
        self.assertEqual("t2.medium", reservations[0]["Instances"][0]["InstanceType"])

        # clean up
        self.cleanup(stack_name)

    def test_cfn_update_different_stack(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        sqs = aws_stack.create_external_boto_client("sqs")

        queue_name = "q-%s" % short_uid()
        template1 = TEST_TEMPLATE_27_1 % queue_name
        template2 = TEST_TEMPLATE_27_2 % queue_name
        stack_name = "stack-%s" % short_uid()
        deploy_cf_stack(stack_name=stack_name, template_body=template1)
        queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]

        cloudformation.update_stack(StackName=stack_name, TemplateBody=template2)
        status = await_stack_completion(stack_name)
        self.assertEqual("UPDATE_COMPLETE", status["StackStatus"])

        queues = sqs.list_queues().get("QueueUrls", [])
        self.assertIn(queue_url, queues)
        result = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        self.assertEqual("5", result["Attributes"]["DelaySeconds"])

        outputs = cloudformation.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl"][0]
        self.assertEqual(queue_url, output)

    def test_cfn_event_bus_resource(self):
        event_client = aws_stack.create_external_boto_client("events")

        def _assert(expected_len):
            rs = event_client.list_event_buses()
            event_buses = [eb for eb in rs["EventBuses"] if eb["Name"] == "my-test-bus"]
            self.assertEqual(expected_len, len(event_buses))
            rs = event_client.list_connections()
            connections = [con for con in rs["Connections"] if con["Name"] == "my-test-conn"]
            self.assertEqual(expected_len, len(connections))

        # deploy stack
        stack_name = "stack-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "template31.yaml"))
        deploy_cf_stack(stack_name=stack_name, template_body=template)
        _assert(1)

        # clean up
        self.cleanup(stack_name)
        _assert(0)

    def test_cfn_statemachine_with_dependencies(self):
        stack_name = "stack-%s" % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, "templates", "statemachine_test.json"))
        deploy_cf_stack(stack_name=stack_name, template_body=template)

        sfn_client = aws_stack.create_external_boto_client("stepfunctions")

        rs = sfn_client.list_state_machines()
        statemachines = [
            sm for sm in rs["stateMachines"] if "{}-SFSM22S5Y".format(stack_name) in sm["name"]
        ]
        self.assertEqual(1, len(statemachines))

        # clean up
        self.cleanup(stack_name)
        time.sleep(2)

        rs = sfn_client.list_state_machines()
        statemachines = [
            sm for sm in rs["stateMachines"] if "{}-SFSM22S5Y".format(stack_name) in sm["name"]
        ]
        self.assertEqual(0, len(statemachines))

    def test_cfn_apigateway_rest_api(self):
        template = load_file(os.path.join(THIS_FOLDER, "templates", "apigateway.json"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        apigw_client = aws_stack.create_external_boto_client("apigateway")

        rs = apigw_client.get_rest_apis()
        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        self.assertEqual(0, len(apis))

        # clean up
        self.cleanup(stack_name)

        stack_name = "stack-%s" % short_uid()

        create_and_await_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{"ParameterKey": "Create", "ParameterValue": "True"}],
        )

        rs = apigw_client.get_rest_apis()
        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        self.assertEqual(1, len(apis))

        rs = apigw_client.get_models(restApiId=apis[0]["id"])
        self.assertEqual(1, len(rs["items"]))

        # clean up
        self.cleanup(stack_name)

        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        self.assertEqual(0, len(apis))

    def test_cfn_with_exports(self):
        cloudformation = aws_stack.create_external_boto_client("cloudformation")

        # fetch initial list of exports
        exports_before = cloudformation.list_exports()["Exports"]

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template32.yaml"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        exports = cloudformation.list_exports()["Exports"]
        self.assertEqual(len(exports_before) + 6, len(exports))
        export_names = [e["Name"] for e in exports]
        self.assertIn("{}-FullAccessCentralControlPolicy".format(stack_name), export_names)
        self.assertIn("{}-ReadAccessCentralControlPolicy".format(stack_name), export_names)
        self.assertIn("{}-cc-groups-stream".format(stack_name), export_names)
        self.assertIn("{}-cc-scenes-stream".format(stack_name), export_names)
        self.assertIn("{}-cc-customscenes-stream".format(stack_name), export_names)
        self.assertIn("{}-cc-schedules-stream".format(stack_name), export_names)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_with_route_table(self):
        ec2_client = aws_stack.create_external_boto_client("ec2")

        resp = ec2_client.describe_vpcs()
        vpcs_before = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template33.yaml"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)
        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        self.assertEqual(1, len(vpcs))

        resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]]}])
        # Each VPC always have 1 default RouteTable
        self.assertEqual(2, len(resp["RouteTables"]))

        # The 2nd RouteTable was created by cfn template
        route_table_id = resp["RouteTables"][1]["RouteTableId"]
        routes = resp["RouteTables"][1]["Routes"]

        # Each RouteTable has 1 default route
        self.assertEqual(2, len(routes))

        self.assertEqual("100.0.0.0/20", routes[0]["DestinationCidrBlock"])

        # The 2nd Route was created by cfn template
        self.assertEqual("0.0.0.0/0", routes[1]["DestinationCidrBlock"])

        cloudformation = aws_stack.create_external_boto_client("cloudformation")
        exports = cloudformation.list_exports()["Exports"]
        export_values = {ex["Name"]: ex["Value"] for ex in exports}
        self.assertIn("publicRoute-identify", export_values)
        self.assertEqual(
            "{}~0.0.0.0/0".format(route_table_id), export_values["publicRoute-identify"]
        )

        # clean up
        self.cleanup(stack_name)

        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        self.assertEqual(0, len(vpcs))

    def test_cfn_with_kms_resources(self):
        kms = aws_stack.create_external_boto_client("kms")
        aliases_before = kms.list_aliases()["Aliases"]

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template34.yaml"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        aliases = kms.list_aliases()["Aliases"]
        self.assertEqual(len(aliases_before) + 1, len(aliases))

        alias_names = [alias["AliasName"] for alias in aliases]
        self.assertIn("alias/sample-kms-alias", alias_names)

        # clean up
        self.cleanup(stack_name)

        aliases = kms.list_aliases()["Aliases"]
        self.assertEqual(len(aliases_before), len(aliases))

        alias_names = [alias["AliasName"] for alias in aliases]
        self.assertNotIn("alias/sample-kms-alias", alias_names)

    def test_cfn_with_apigateway_resources(self):
        template = load_file(os.path.join(THIS_FOLDER, "templates", "template35.yaml"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)
        apigw_client = aws_stack.create_external_boto_client("apigateway")
        apis = [
            api
            for api in apigw_client.get_rest_apis()["items"]
            if api["name"] == "celeste-Gateway-local"
        ]
        self.assertEqual(1, len(apis))
        api_id = apis[0]["id"]

        resources = [
            res
            for res in apigw_client.get_resources(restApiId=api_id)["items"]
            if res.get("pathPart") == "account"
        ]

        self.assertEqual(1, len(resources))

        # assert request parameter is present in resource method
        self.assertEqual(
            {"method.request.path.account": True},
            resources[0]["resourceMethods"]["POST"]["requestParameters"],
        )
        models = [
            model
            for model in apigw_client.get_models(restApiId=api_id)["items"]
            if stack_name in model["name"]
        ]

        self.assertEqual(2, len(models))

        # clean up
        self.cleanup(stack_name)

        apis = [
            api
            for api in apigw_client.get_rest_apis()["items"]
            if api["name"] == "celeste-Gateway-local"
        ]
        self.assertEqual(0, len(apis))

    def test_dynamodb_stream_response_with_cf(self):

        dynamodb = aws_stack.create_external_boto_client("dynamodb")
        template = TEST_TEMPLATE_28 % "EventTable"
        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)

        response = dynamodb.describe_kinesis_streaming_destination(TableName="EventTable")

        self.assertEqual("EventTable", response.get("TableName"))
        self.assertEqual(1, len(response.get("KinesisDataStreamDestinations")))
        self.assertIn("StreamArn", response.get("KinesisDataStreamDestinations")[0])

    def test_updating_stack_with_iam_role(self):
        lambda_client = aws_stack.create_external_boto_client("lambda")
        iam = aws_stack.create_external_boto_client("iam")

        # Initialization
        stack_name = "stack-%s" % short_uid()
        lambda_role_name = "lambda-role-%s" % short_uid()
        lambda_function_name = "lambda-function-%s" % short_uid()

        template = json.loads(load_file(TEST_TEMPLATE_7))

        template["Resources"]["LambdaExecutionRole"]["Properties"]["RoleName"] = lambda_role_name
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name

        # Create stack and wait for 'CREATE_COMPLETE' status of the stack
        rs = create_and_await_stack(StackName=stack_name, TemplateBody=json.dumps(template))

        # Checking required values for Lambda function and IAM Role
        self.assertIn("StackId", rs)
        self.assertIn(stack_name, rs["StackId"])

        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )
        list_roles = list_all_resources(
            lambda kwargs: iam.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name
        ]
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name]

        self.assertEqual(1, len(new_function))
        self.assertIn(lambda_role_name, new_function[0].get("Role"))

        self.assertEqual(1, len(new_role))

        # Generate new names for lambda and IAM Role
        lambda_role_name_new = "lambda-role-%s" % short_uid()
        lambda_function_name_new = "lambda-function-%s" % short_uid()

        template["Resources"]["LambdaExecutionRole"]["Properties"][
            "RoleName"
        ] = lambda_role_name_new
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name_new

        # Update stack and wait for 'UPDATE_COMPLETE' status of the stack
        rs = update_and_await_stack(stack_name, TemplateBody=json.dumps(template))

        # Checking new required values for Lambda function and IAM Role
        self.assertIn("StackId", rs)
        self.assertIn(stack_name, rs["StackId"])

        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )

        list_roles = list_all_resources(
            lambda kwargs: iam.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name_new
        ]
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name_new]

        self.assertEqual(1, len(new_function))
        self.assertIn(lambda_role_name_new, new_function[0].get("Role"))

        self.assertEqual(1, len(new_role))

        # Delete the stack and wait for the status 'DELETE_COMPLETE' of the stack
        delete_and_await_stack(stack_name)

    def test_cfn_with_multiple_route_tables(self):
        ec2_client = aws_stack.create_external_boto_client("ec2")

        resp = ec2_client.describe_vpcs()
        vpcs_before = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template36.yaml"))

        stack_name = "stack-%s" % short_uid()
        create_and_await_stack(StackName=stack_name, TemplateBody=template)
        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        self.assertEqual(1, len(vpcs))

        resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]]}])
        # Cloudformation Template will create more than one route table 2 in template + default
        self.assertEqual(3, len(resp["RouteTables"]))

        # Clean up
        self.cleanup(stack_name)

    def test_cfn_with_multiple_route_table_associations(self):
        ec2_client = aws_stack.create_external_boto_client("ec2")

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template37.yaml"))

        stack_name = "stack-%s" % short_uid()

        details = create_and_await_stack(StackName=stack_name, TemplateBody=template)
        route_table_id = [
            out["OutputValue"] for out in details["Outputs"] if out["OutputKey"] == "RouteTable"
        ][0]
        route_table = ec2_client.describe_route_tables(
            Filters=[{"Name": "route-table-id", "Values": [route_table_id]}]
        )["RouteTables"][0]

        # # Cloudformation Template will create more than one route table 2 in template + default
        self.assertEqual(2, len(route_table["Associations"]))

        # Clean up
        self.cleanup(stack_name)
