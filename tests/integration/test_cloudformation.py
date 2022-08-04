import json
import os
import time

import pytest
import yaml
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.testing.aws.util import bucket_exists
from localstack.utils.aws import aws_stack
from localstack.utils.cloudformation import template_preparer
from localstack.utils.common import load_file, short_uid, to_str
from localstack.utils.sync import poll_condition, retry, wait_until
from localstack.utils.testutil import create_zip_file, list_all_resources

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

TEST_TEMPLATE_3 = (
    """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
"""
    % short_uid()
)

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
    % get_aws_account_id()
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
      ElasticsearchClusterConfig:
        InstanceCount: 1
        InstanceType: 'm5.large.elasticsearch'
        ZoneAwarenessEnabled: false
        # remaining required attributes (DedicatedMasterType, WarmType) should get filled in by template deployer
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
    % get_aws_account_id()
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

TEST_TEMPLATE_29 = """
Parameters:
  Qualifier:
    Type: String
    Default: q123
Resources:
  TestQueue:
    Type: AWS::SQS::Queue
    Properties:
      QueueName: %s
      Tags:
        - Key: test
          Value: !Sub "arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter${CdkBootstrapVersion}"
  CdkBootstrapVersion:
    Type: "AWS::SSM::Parameter"
    Properties:
      Type: String
      Name: !Sub "/cdk-bootstrap/${Qualifier}/version"
      Value: "..."
"""


# Note: Do not add new tests here !
class TestCloudFormation:
    # TODO: split up file
    # TODO: remove all aws_stack usage

    # TODO: this is actually exactly the opposite
    def test_list_stack_events(self, cfn_client):
        response = cfn_client.describe_stack_events()
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

    def test_validate_template(self, cfn_client):
        template = template_preparer.template_to_json(
            load_file(os.path.join(THIS_FOLDER, "templates", "valid_template.json"))
        )
        resp = cfn_client.validate_template(TemplateBody=template)

        assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200
        assert len(resp["Parameters"]) == 1
        assert resp["Parameters"][0]["ParameterKey"] == "KeyExample"
        assert (
            resp["Parameters"][0]["Description"]
            == "The EC2 Key Pair to allow SSH access to the instance"
        )

    def test_validate_invalid_json_template_should_fail(self, cfn_client):
        invalid_json = '{"this is invalid JSON"="bobbins"}'

        with pytest.raises((ClientError, ResponseParserError)) as ctx:
            cfn_client.validate_template(TemplateBody=invalid_json)
        if isinstance(ctx.value, ClientError):
            assert ctx.value.response["ResponseMetadata"]["HTTPStatusCode"] == 400
            assert ctx.value.response["Error"]["Message"] == "Template Validation Error"

    def test_list_stack_resources_returns_queue_urls(
        self, deploy_cfn_template, sqs_client, sns_client, cfn_client
    ):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template27.yaml")
        )

        stack_summaries = cfn_client.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        queue_urls = sqs_client.list_queues()["QueueUrls"]
        topic_arns = [t["TopicArn"] for t in sns_client.list_topics()["Topics"]]

        stack_queues = [r for r in stack_summaries if r["ResourceType"] == "AWS::SQS::Queue"]
        for resource in stack_queues:
            assert resource["PhysicalResourceId"] in queue_urls

        stack_topics = [r for r in stack_summaries if r["ResourceType"] == "AWS::SNS::Topic"]
        for resource in stack_topics:
            assert resource["PhysicalResourceId"] in topic_arns

        # assert that stack outputs are returned properly
        # TODO: better support in fixture for stack exports
        describe_stack_result = cfn_client.describe_stacks(StackName=stack.stack_id)
        output = describe_stack_result["Stacks"][0]["Outputs"][0]
        assert output["ExportName"] == "T27SQSQueue-URL"
        assert config.DEFAULT_REGION in output["OutputValue"]  # TODO: that doesn't seem right

    def test_create_change_set(self, cfn_client, deploy_cfn_template):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_3)

        # create change set with the same template (no changes)
        response = cfn_client.create_change_set(
            StackName=stack.stack_name,
            TemplateBody=TEST_TEMPLATE_3,
            ChangeSetName="nochanges",
        )
        assert f":{get_aws_account_id()}:changeSet/nochanges/" in response["Id"]
        assert f":{get_aws_account_id()}:stack/" in response["StackId"]

    def test_sam_template(self, lambda_client, deploy_cfn_template):

        # deploy template
        func_name = f"test-{short_uid()}"
        template = load_file(os.path.join(THIS_FOLDER, "templates/template4.yaml")) % func_name
        deploy_cfn_template(template=template)

        # run Lambda test invocation
        result = lambda_client.invoke(FunctionName=func_name)
        result = json.loads(to_str(result["Payload"].read()))
        assert result == {"hello": "world"}

    def test_nested_stack(self, s3_client, cfn_client, deploy_cfn_template, s3_create_bucket):
        # upload template to S3
        artifacts_bucket = f"cf-artifacts-{short_uid()}"
        artifacts_path = "stack.yaml"
        s3_create_bucket(Bucket=artifacts_bucket, ACL="public-read")
        s3_client.put_object(
            Bucket=artifacts_bucket,
            Key=artifacts_path,
            Body=load_file(os.path.join(THIS_FOLDER, "templates", "template5.yaml")),
        )

        # deploy template
        param_value = short_uid()
        stack_bucket_name = f"test-{param_value}"  # this is the bucket name generated by template5

        deploy_cfn_template(
            template=load_file(os.path.join(THIS_FOLDER, "templates", "template6.yaml"))
            % (artifacts_bucket, artifacts_path),
            parameters={"GlobalParam": param_value},
        )

        # assert that nested resources have been created
        def assert_bucket_exists():
            response = s3_client.head_bucket(Bucket=stack_bucket_name)
            assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]

        retry(assert_bucket_exists)

    def test_create_cfn_lambda_without_function_name(
        self, lambda_client, cfn_client, deploy_cfn_template
    ):
        lambda_role_name = f"lambda-role-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template7.json"),
            parameters={"LambdaRoleName": lambda_role_name},
        )

        assert "TestStackFunctionName" in stack.outputs
        stack_function_name = stack.outputs["TestStackFunctionName"]

        # Check that the function has been created
        def stack_function_exists():
            response = lambda_client.get_function(FunctionName=stack_function_name)
            assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        retry(stack_function_exists)

        response = lambda_client.get_function(FunctionName=stack_function_name)
        assert response["Configuration"]["Runtime"] == "nodejs12.x"
        assert response["Configuration"]["Handler"] == "index.handler"
        assert lambda_role_name in response["Configuration"]["Role"]

        # delete the stack
        stack.destroy()

        # check that function was removed
        def stack_function_removed():
            with pytest.raises(ClientError) as e:
                lambda_client.get_function(FunctionName=stack_function_name)
            assert e.match("ResourceNotFoundException")

        retry(stack_function_removed)

    def test_deploy_stack_with_iam_role(self, cfn_client, iam_client, deploy_cfn_template):
        role_name = f"role-{short_uid()}"

        stack = deploy_cfn_template(
            template=load_file(os.path.join(THIS_FOLDER, "templates", "deploy_template_1.yaml"))
            % role_name
        )

        def iam_role_exists(_role_name):
            response = iam_client.list_roles()
            for role in response.get("Roles", []):
                if role["RoleName"] == _role_name:
                    return True
            return False

        assert poll_condition(
            lambda: iam_role_exists(role_name), timeout=10
        ), f"expected role {role_name} to be created"

        # TODO:? why is it deleting the policy here
        rs = iam_client.list_role_policies(RoleName=role_name)
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=rs["PolicyNames"][0])

        stack.destroy()

        assert poll_condition(
            lambda: not iam_role_exists(role_name), timeout=10
        ), f"expected role {role_name} to be removed"

    def test_deploy_stack_with_sns_topic(self, sns_client, deploy_cfn_template):

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/deploy_template_2.yaml"),
            parameters={"CompanyName": "MyCompany", "MyEmail1": "my@email.com"},
        )
        assert len(stack.outputs) == 3

        topic_arn = stack.outputs["MyTopic"]
        rs = sns_client.list_topics()

        # Topic resource created
        topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
        assert len(topics) == 1

        stack.destroy()

        # assert topic resource removed
        rs = sns_client.list_topics()
        topics = [tp for tp in rs["Topics"] if tp["TopicArn"] == topic_arn]
        assert not topics

    def test_deploy_stack_with_dynamodb_table(
        self, cfn_client, deploy_cfn_template, dynamodb_client
    ):
        env = "Staging"
        ddb_table_name_prefix = f"ddb-table-{short_uid()}"
        ddb_table_name = f"{ddb_table_name_prefix}-{env}"

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/deploy_template_3.yaml"),
            parameters={"tableName": ddb_table_name_prefix, "env": env},
        )

        assert stack.outputs["Arn"].startswith("arn:aws:dynamodb")
        assert f"table/{ddb_table_name}" in stack.outputs["Arn"]
        assert stack.outputs["Name"] == ddb_table_name

        rs = dynamodb_client.list_tables()
        assert ddb_table_name in rs["TableNames"]

        stack.destroy()

        rs = dynamodb_client.list_tables()
        assert ddb_table_name not in rs["TableNames"]

    def test_deploy_stack_with_iam_nested_policy(self, deploy_cfn_template):
        deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/deploy_template_4.yaml")
        )

    def test_cfn_handle_s3_bucket_resources(self, s3_client, deploy_cfn_template):
        bucket_name = f"s3-bucket-{short_uid()}"

        TEST_TEMPLATE_8["Resources"]["S3Bucket"]["Properties"]["BucketName"] = bucket_name
        template_body = json.dumps(TEST_TEMPLATE_8)

        assert not bucket_exists(s3_client, bucket_name)

        stack = deploy_cfn_template(template=template_body)

        assert bucket_exists(s3_client, bucket_name)
        rs = s3_client.get_bucket_policy(Bucket=bucket_name)
        assert "Policy" in rs
        policy_doc = TEST_TEMPLATE_8["Resources"]["S3BucketPolicy"]["Properties"]["PolicyDocument"]
        assert json.loads(rs["Policy"]) == policy_doc

        # clean up, assert resources deleted
        stack.destroy()

        assert not bucket_exists(s3_client, bucket_name)
        with pytest.raises(ClientError) as ctx:
            s3_client.get_bucket_policy(Bucket=bucket_name)
        assert ctx.value.response["Error"]["Code"] == "NoSuchBucket"

        # recreate stack
        deploy_cfn_template(stack_name=stack.stack_name, template=template_body, is_update=True)

    def test_cfn_handle_log_group_resource(self, deploy_cfn_template, logs_client):
        log_group_prefix = "/aws/lambda/AWS_DUB_LAM_10000000"

        stack = deploy_cfn_template(template=TEST_TEMPLATE_9)

        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
        assert len(rs["logGroups"]) == 1
        assert (
            rs["logGroups"][0]["logGroupName"]
            == "/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev"
        )

        # clean up and assert deletion
        stack.destroy()
        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
        assert len(rs["logGroups"]) == 0

    @pytest.mark.skip_offline
    def test_cfn_handle_elasticsearch_domain(self, es_client, deploy_cfn_template):
        domain_name = f"es-{short_uid()}"

        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_10, parameters={"DomainName": domain_name}
        )
        assert len(stack.outputs) == 4

        rs = es_client.describe_elasticsearch_domain(DomainName=domain_name)
        status = rs["DomainStatus"]
        assert status["DomainName"] == domain_name
        assert stack.outputs["MyElasticsearchArn"] == status["ARN"]
        assert stack.outputs["MyElasticsearchDomainArn"] == status["ARN"]
        assert stack.outputs["MyElasticsearchDomainEndpoint"] == status["Endpoint"]
        assert stack.outputs["MyElasticsearchRef"] == status["DomainName"]

        tags = es_client.list_tags(ARN=status["ARN"])["TagList"]
        assert tags == [{"Key": "k1", "Value": "v1"}, {"Key": "k2", "Value": "v2"}]

    def test_cfn_handle_secretsmanager_secret(
        self, secretsmanager_client, deploy_cfn_template, cfn_client
    ):
        secret_name = f"secret-{short_uid()}"
        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_11, parameters={"SecretName": secret_name}
        )

        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
        assert rs["Name"] == secret_name
        assert "DeletedDate" not in rs

        cfn_client.delete_stack(StackName=stack.stack_name)
        assert wait_until(
            lambda: cfn_client.describe_stacks(StackName=stack.stack_id)["Stacks"][0]["StackStatus"]
            == "DELETE_COMPLETE"
        )

        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
        assert "DeletedDate" in rs

    def test_cfn_handle_kinesis_firehose_resources(
        self, kinesis_client, firehose_client, deploy_cfn_template
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

    def test_cfn_handle_iam_role_resource(self, deploy_cfn_template, iam_client):
        role_name = f"role-{short_uid()}"
        policy_name = f"policy-{short_uid()}"
        role_path_prefix = f"/role-prefix-{short_uid()}/"

        template_body = TEST_TEMPLATE_13 % (role_name, role_path_prefix, policy_name)
        stack = deploy_cfn_template(template=template_body)

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)

        assert len(rs["Roles"]) == 1
        role = rs["Roles"][0]
        assert role["RoleName"] == role_name

        result = iam_client.get_policy(PolicyArn=aws_stack.policy_arn(policy_name))
        assert result["Policy"]["PolicyName"] == policy_name

        # clean up
        stack.destroy()

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert not rs["Roles"]

    def test_cfn_handle_iam_role_resource_no_role_name(self, iam_client, deploy_cfn_template):
        role_path_prefix = f"/role-prefix-{short_uid()}/"
        stack = deploy_cfn_template(template=TEST_TEMPLATE_14 % role_path_prefix)

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert len(rs["Roles"]) == 1

        stack.destroy()

        rs = iam_client.list_roles(PathPrefix=role_path_prefix)
        assert not rs["Roles"]

    def test_describe_template(self, s3_client, cfn_client, s3_create_bucket):
        bucket_name = f"b-{short_uid()}"
        template_body = TEST_TEMPLATE_12 % "test-firehose-role-name"
        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(Bucket=bucket_name, Key="template.yml", Body=template_body)

        template_url = f"{config.get_edge_url()}/{bucket_name}/template.yml"

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

    # TODO: re-write this
    @pytest.mark.skip(reason="flaky due to issues in parameter handling and re-resolving")
    def test_stack_imports(self, deploy_cfn_template, cfn_client, sqs_client):
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
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl1"][
            0
        ]
        assert aws_stack.sqs_queue_arn(queue_url1) == output  # TODO
        output = [out["OutputValue"] for out in outputs if out["OutputKey"] == "MessageQueueUrl2"][
            0
        ]
        assert output == queue_url2

    def test_cfn_conditional_deployment(self, s3_client, deploy_cfn_template):
        bucket_id = short_uid()
        deploy_cfn_template(template=TEST_TEMPLATE_19.format(id=bucket_id))

        buckets = s3_client.list_buckets()["Buckets"]
        dev_bucket = f"cf-dev-{bucket_id}"
        prd_bucket = f"cf-prd-{bucket_id}"
        dev_bucket = [b for b in buckets if b["Name"] == dev_bucket]
        prd_bucket = [b for b in buckets if b["Name"] == prd_bucket]

        assert not prd_bucket
        assert dev_bucket

    def test_cfn_handle_sqs_resource(self, deploy_cfn_template, sqs_client):
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

    def test_cfn_handle_events_rule(self, events_client, deploy_cfn_template):
        bucket_name = f"target-{short_uid()}"
        rule_prefix = f"s3-rule-{short_uid()}"
        rule_name = f"{rule_prefix}-{short_uid()}"

        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_16 % (bucket_name, rule_name),
        )

        rs = events_client.list_rules(NamePrefix=rule_prefix)
        assert rule_name in [rule["Name"] for rule in rs["Rules"]]

        target_arn = aws_stack.s3_bucket_arn(bucket_name)
        rs = events_client.list_targets_by_rule(Rule=rule_name)
        assert target_arn in [target["Arn"] for target in rs["Targets"]]

        # clean up
        stack.destroy()
        rs = events_client.list_rules(NamePrefix=rule_prefix)
        assert rule_name not in [rule["Name"] for rule in rs["Rules"]]

    def test_cfn_handle_events_rule_without_name(self, events_client, deploy_cfn_template):
        rs = events_client.list_rules()
        rule_names = [rule["Name"] for rule in rs["Rules"]]

        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_18 % aws_stack.role_arn("sfn_role"),  # TODO: !
        )

        rs = events_client.list_rules()
        new_rules = [rule for rule in rs["Rules"] if rule["Name"] not in rule_names]
        assert len(new_rules) == 1
        rule = new_rules[0]

        assert rule["ScheduleExpression"] == "cron(0/1 * * * ? *)"

        stack.destroy()

        rs = events_client.list_rules()
        assert rule["Name"] not in [r["Name"] for r in rs["Rules"]]

    @pytest.mark.parametrize(
        "create_bucket_first, region", [(True, "eu-west-1"), (False, "us-east-1")]
    )
    def test_cfn_handle_s3_notification_configuration(
        self,
        region,
        create_boto_client,
        deploy_cfn_template,
        create_bucket_first,
    ):
        s3_client = create_boto_client("s3", region_name=region)
        bucket_name = f"target-{short_uid()}"
        queue_name = f"queue-{short_uid()}"
        queue_arn = aws_stack.sqs_queue_arn(queue_name, region_name=s3_client.meta.region_name)
        if create_bucket_first:
            s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": s3_client.meta.region_name},
            )
        stack = deploy_cfn_template(
            template=TEST_TEMPLATE_17 % (queue_name, bucket_name, queue_arn),
        )
        rs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        assert "QueueConfigurations" in rs
        assert len(rs["QueueConfigurations"]) == 1
        assert rs["QueueConfigurations"][0]["QueueArn"] == queue_arn

        stack.destroy()

        # exception below tested against AWS
        with pytest.raises(Exception) as exc:
            s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        exc.match("NoSuchBucket")

    # TODO: re-evaluate purpose
    def test_cfn_lambda_function_with_iam_role(self, iam_client, deploy_cfn_template, cleanups):
        role_name = f"lambda-ex-{short_uid()}"
        try:
            response = iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {'
                '"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}',
            )
            assert response["Role"]["RoleName"] == role_name

            response = iam_client.get_role(RoleName=role_name)
            assert response["Role"]["RoleName"] == role_name

            role_arn = response["Role"]["Arn"]
            deploy_cfn_template(template=TEST_TEMPLATE_20 % role_arn)
        finally:
            iam_client.delete_role(RoleName=role_name)

    def test_cfn_handle_serverless_api_resource(
        self, deploy_cfn_template, cfn_client, apigateway_client
    ):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_22)

        res = cfn_client.list_stack_resources(StackName=stack.stack_name)["StackResourceSummaries"]
        rest_api_ids = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]
        lambda_func_names = [
            r["PhysicalResourceId"] for r in res if r["ResourceType"] == "AWS::Lambda::Function"
        ]

        assert len(rest_api_ids) == 1
        assert len(lambda_func_names) == 1

        rs = apigateway_client.get_resources(restApiId=rest_api_ids[0])
        assert len(rs["items"]) == 1
        resource = rs["items"][0]

        uri = resource["resourceMethods"]["GET"]["methodIntegration"]["uri"]
        lambda_arn = aws_stack.lambda_function_arn(lambda_func_names[0])  # TODO
        assert lambda_arn in uri

    def test_cfn_with_on_demand_dynamodb_resource(self, deploy_cfn_template):
        deploy_cfn_template(template_path=os.path.join(THIS_FOLDER, "templates/template21.json"))

    # TODO: refactor
    def test_update_lambda_function(
        self, lambda_client, cfn_client, s3_client, s3_create_bucket, deploy_cfn_template
    ):
        bucket_name = f"bucket-{short_uid()}"
        key_name = "lambda-package"
        role_name = f"role-{short_uid()}"
        function_name = f"func-{short_uid()}"
        package_path = os.path.join(THIS_FOLDER, "awslambda/functions/lambda_echo.js")
        template = json.loads(
            load_file(os.path.join(THIS_FOLDER, "templates/update_lambda_template.json"))
        )
        template["Resources"]["PullMarketsRole"]["Properties"]["RoleName"] = role_name

        props = template["Resources"]["SomeNameFunction"]["Properties"]
        props["Code"]["S3Bucket"] = bucket_name
        props["Code"]["S3Key"] = key_name
        props["FunctionName"] = function_name

        s3_create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key_name,
            Body=create_zip_file(package_path, get_content=True),
        )

        stack = deploy_cfn_template(template=json.dumps(template))

        props.update({"Environment": {"Variables": {"AWS_NODEJS_CONNECTION_REUSE_ENABLED": 1}}})
        deploy_cfn_template(
            stack_name=stack.stack_name, template=json.dumps(template), is_update=True
        )

        rs = lambda_client.get_function(FunctionName=function_name)
        assert rs["Configuration"]["FunctionName"] == function_name
        assert (
            "AWS_NODEJS_CONNECTION_REUSE_ENABLED" in rs["Configuration"]["Environment"]["Variables"]
        )

    def test_cfn_deploy_apigateway_integration(
        self, deploy_cfn_template, s3_client, cfn_client, apigateway_client
    ):
        bucket_name = "hofund-local-deployment"
        key_name = "serverless/hofund/local/1599143878432/authorizer.zip"
        package_path = os.path.join(THIS_FOLDER, "awslambda/functions/lambda_echo.js")
        template = template_preparer.template_to_json(
            load_file(os.path.join(THIS_FOLDER, "templates/apigateway_integration.json"))
        )

        s3_client.create_bucket(Bucket=bucket_name, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket_name,
            Key=key_name,
            Body=create_zip_file(package_path, get_content=True),
        )

        stack = deploy_cfn_template(template=template)
        stack_resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        rest_apis = [
            res for res in stack_resources if res["ResourceType"] == "AWS::ApiGateway::RestApi"
        ]
        rs = apigateway_client.get_rest_api(restApiId=rest_apis[0]["PhysicalResourceId"])
        assert rs["name"] == "ApiGatewayRestApi"

    def test_globalindex_read_write_provisioned_throughput_dynamodb_table(
        self, dynamodb_client, deploy_cfn_template
    ):
        deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/deploy_template_3.yaml"),
            parameters={"tableName": "dynamodb", "env": "test"},
        )

        response = dynamodb_client.describe_table(TableName="dynamodb-test")

        if response["Table"]["ProvisionedThroughput"]:
            throughput = response["Table"]["ProvisionedThroughput"]
            assert isinstance(throughput["ReadCapacityUnits"], int)
            assert isinstance(throughput["WriteCapacityUnits"], int)

        for global_index in response["Table"]["GlobalSecondaryIndexes"]:
            index_provisioned = global_index["ProvisionedThroughput"]
            test_read_capacity = index_provisioned["ReadCapacityUnits"]
            test_write_capacity = index_provisioned["WriteCapacityUnits"]
            assert isinstance(test_read_capacity, int)
            assert isinstance(test_write_capacity, int)

    # TODO: evaluate
    def test_update_conditions(self, s3_client, cfn_client, deploy_cfn_template):
        stack = deploy_cfn_template(template=TEST_TEMPLATE_3)
        template = yaml.load(TEST_TEMPLATE_3)

        # TODO: avoid changing template here
        # update stack with additional resources and conditions
        bucket1 = f"b-{short_uid()}"
        bucket2 = f"b-{short_uid()}"
        template["Resources"].update(
            {
                "ToBeCreated": {
                    "Type": "AWS::S3::Bucket",
                    "Condition": "TrueCondition",
                    "Properties": {"BucketName": bucket1},
                },
                "NotToBeCreated": {
                    "Type": "AWS::S3::Bucket",
                    "Condition": "FalseCondition",
                    "Properties": {"BucketName": bucket2},
                },
            }
        )
        template["Conditions"] = {
            "TrueCondition": {"Fn::Equals": ["same", "same"]},
            "FalseCondition": {"Fn::Equals": ["this", "other"]},
        }
        cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=json.dumps(template))
        cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

        # bucket1 should have been created, bucket2 not
        s3_client.head_bucket(Bucket=bucket1)
        with pytest.raises(Exception):
            s3_client.head_bucket(Bucket=bucket2)

    def test_update_stack_with_same_template(self, cfn_client, deploy_cfn_template):
        template = load_file(os.path.join(THIS_FOLDER, "templates/fifo_queue.json"))
        stack = deploy_cfn_template(template=template)

        with pytest.raises(Exception) as ctx:  # TODO: capture proper exception
            cfn_client.update_stack(StackName=stack.stack_name, TemplateBody=template)
            cfn_client.get_waiter("stack_update_complete").wait(StackName=stack.stack_name)

        error_message = str(ctx.value)
        assert "UpdateStack" in error_message
        assert "No updates are to be performed." in error_message

    # TODO: remove this and replace with CDK test
    def test_cdk_template(self, s3_client, lambda_client, deploy_cfn_template, s3_create_bucket):
        bucket = f"bucket-{short_uid()}"
        key = f"key-{short_uid()}"
        path = os.path.join(THIS_FOLDER, "templates/asset")

        s3_create_bucket(Bucket=bucket)
        s3_client.put_object(Bucket=bucket, Key=key, Body=create_zip_file(path, get_content=True))

        template = load_file(os.path.join(THIS_FOLDER, "templates", "cdktemplate.json"))

        stack = deploy_cfn_template(
            template=template,
            parameters={
                "AssetParameters1S3BucketEE4ED9A8": bucket,
                "AssetParameters1S3VersionKeyE160C88A": key,
            },
        )

        resp = lambda_client.list_functions()
        functions = [func for func in resp["Functions"] if stack.stack_name in func["FunctionName"]]

        assert len(functions) == 2
        assert (
            len([func for func in functions if func["Handler"] == "index.createUserHandler"]) == 1
        )
        assert (
            len([func for func in functions if func["Handler"] == "index.authenticateUserHandler"])
            == 1
        )

    def test_cfn_template_with_short_form_fn_sub(
        self, iam_client, deploy_cfn_template, stepfunctions_client
    ):
        environment = f"env-{short_uid()}"

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template23.yaml"),
            parameters={"Environment": environment, "ApiKey": "12345"},
        )

        # 2 roles created successfully
        rs = iam_client.list_roles()
        roles = [role for role in rs["Roles"] if stack.stack_name in role["RoleName"]]
        assert len(roles) == 2

        state_machines_after = stepfunctions_client.list_state_machines()["stateMachines"]
        state_machines = [
            sm for sm in state_machines_after if f"{stack.stack_name}-StateMachine-" in sm["name"]
        ]
        assert len(state_machines) == 1

        rs = stepfunctions_client.describe_state_machine(
            stateMachineArn=state_machines[0]["stateMachineArn"]
        )
        definition = json.loads(rs["definition"].replace("\n", ""))
        payload = definition["States"]["time-series-update"]["Parameters"]["Payload"]
        assert payload == {"key": "12345"}

    def test_sub_in_lambda_function_name(
        self, s3_client, lambda_client, rg_client, deploy_cfn_template, s3_create_bucket
    ):
        environment = f"env-{short_uid()}"
        bucket = f"bucket-{short_uid()}"
        key = f"key-{short_uid()}"

        package_path = os.path.join(THIS_FOLDER, "awslambda/functions/lambda_echo.js")

        s3_create_bucket(Bucket=bucket, ACL="public-read")
        s3_client.put_object(
            Bucket=bucket, Key=key, Body=create_zip_file(package_path, get_content=True)
        )
        time.sleep(1)  # TODO: ? what is this waiting for

        template = load_file(os.path.join(THIS_FOLDER, "templates", "template24.yaml")) % (
            bucket,
            key,
            bucket,
            key,
        )
        deploy_cfn_template(template=template, parameters={"Environment": environment})

        functions = lambda_client.list_functions()["Functions"]
        # assert Lambda functions created with expected name and ARN
        func_prefix = f"test-{environment}-connectionHandler"
        functions = [func for func in functions if func["FunctionName"].startswith(func_prefix)]
        assert len(functions) == 2
        func1 = [f for f in functions if f["FunctionName"].endswith("connectionHandler1")][0]
        func2 = [f for f in functions if f["FunctionName"].endswith("connectionHandler2")][0]
        assert func1["FunctionArn"].endswith(func1["FunctionName"])
        assert func2["FunctionArn"].endswith(func2["FunctionName"])

        # assert buckets which reference Lambda names have been created
        buckets = s3_client.list_buckets()["Buckets"]
        buckets = [b for b in buckets if b["Name"].startswith(func_prefix.lower())]
        # assert buckets are created correctly
        assert len(functions) == 2
        tags1 = s3_client.get_bucket_tagging(Bucket=buckets[0]["Name"])
        tags2 = s3_client.get_bucket_tagging(Bucket=buckets[1]["Name"])
        # assert correct tags - they reference the function names and should equal the bucket names (lower case)
        assert buckets[0]["Name"] == tags1["TagSet"][0]["Value"].lower()
        assert buckets[1]["Name"] == tags2["TagSet"][0]["Value"].lower()

        # assert additional resources are present
        rg_name = "cf-rg-6427"
        groups = rg_client.list_groups().get("Groups", [])
        assert [g for g in groups if g["Name"] == rg_name]

    def test_lambda_dependency(self, lambda_client, cfn_client, deploy_cfn_template):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template25.yaml")
        )

        # assert Lambda function created properly
        resp = lambda_client.list_functions()
        func_name = "test-forward-sns"
        functions = [func for func in resp["Functions"] if func["FunctionName"] == func_name]
        assert len(functions) == 1

        # assert that stack outputs are returned properly
        assert len(stack.outputs) == 1
        # TODO(DS)
        # assert outputs[0]["ExportName"] == "FuncArnExportName123"

    def test_functions_in_output_export_name(self, cfn_client, sns_client, deploy_cfn_template):
        environment = f"env-{short_uid()}"

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template26.yaml"),
            parameters={"Environment": environment},
        )

        resp = cfn_client.describe_stacks(StackName=stack.stack_name)
        stack_outputs = [s["Outputs"] for s in resp["Stacks"] if s["StackName"] == stack.stack_name]
        assert len(stack_outputs) == 1

        outputs = {
            o["OutputKey"]: {"value": o["OutputValue"], "export": o["ExportName"]}
            for o in stack_outputs[0]
        }

        assert "VpcId" in outputs
        assert outputs["VpcId"].get("export") == f"{environment}-vpc-id"

        topic_arn = aws_stack.sns_topic_arn(f"{environment}-slack-sns-topic")  # TODO(!)
        assert "TopicArn" in outputs
        assert outputs["TopicArn"].get("export") == topic_arn

        # clean up
        stack.destroy()

        topic_arns = [t["TopicArn"] for t in sns_client.list_topics()["Topics"]]
        assert topic_arn not in topic_arns

    def test_deploy_stack_with_kms(self, kms_client, deploy_cfn_template, cfn_client):
        environment = f"env-{short_uid()}"

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "cdk_template_with_kms.json"),
            parameters={"Environment": environment},
        )

        resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
            "StackResourceSummaries"
        ]
        kmskeys = [res for res in resources if res["ResourceType"] == "AWS::KMS::Key"]

        assert len(kmskeys) == 1
        assert kmskeys[0]["LogicalResourceId"] == "kmskeystack8A5DBE89"
        key_id = kmskeys[0]["PhysicalResourceId"]

        stack.destroy()

        resp = kms_client.describe_key(KeyId=key_id)["KeyMetadata"]
        assert resp["KeyState"] == "PendingDeletion"

    # TODO: refactor
    def test_deploy_stack_with_sub_select_and_sub_getaz(
        self, cfn_client, sns_client, cloudwatch_client, ec2_client, iam_client, deploy_cfn_template
    ):
        ec2_client.create_key_pair(KeyName="key-pair-foo123")

        # list resources before stack deployment
        metric_alarms = cloudwatch_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms = cloudwatch_client.describe_alarms().get("CompositeAlarms", [])

        # deploy stack
        deploy_cfn_template(template_path=os.path.join(THIS_FOLDER, "templates", "template28.yaml"))
        exports = cfn_client.list_exports()["Exports"]

        subnets = [export for export in exports if export["Name"] == "public-sn-a"]
        instances = [export for export in exports if export["Name"] == "RegmonEc2InstanceId"]

        assert len(subnets) == 1
        assert len(instances) == 1

        subnet_id = subnets[0]["Value"]
        instance_id = instances[0]["Value"]

        resp = ec2_client.describe_subnets(SubnetIds=[subnet_id])
        assert len(resp["Subnets"]) == 1

        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        assert len(resp["Reservations"][0]["Instances"]) == 1

        # assert creation of further resources
        resp = sns_client.list_topics()
        topic_arns = [tp["TopicArn"] for tp in resp["Topics"]]
        assert aws_stack.sns_topic_arn("companyname-slack-topic") in topic_arns  # TODO: manual ARN
        # TODO: fix assertions, to make tests parallelizable!
        metric_alarms_after = cloudwatch_client.describe_alarms().get("MetricAlarms", [])
        composite_alarms_after = cloudwatch_client.describe_alarms().get("CompositeAlarms", [])
        assert len(metric_alarms_after) == len(metric_alarms) + 1
        assert len(composite_alarms_after) == len(composite_alarms) + 1

        profiles = iam_client.list_instance_profiles().get("InstanceProfiles", [])
        assert len(profiles) > 0
        profile = profiles[0]
        assert len(profile["Roles"]) > 0

    # TODO: refactor
    @pytest.mark.skip(reason="update doesn't change value for instancetype")
    def test_cfn_update_ec2_instance_type(self, cfn_client, ec2_client, deploy_cfn_template):
        if cfn_client.meta.region_name not in [
            "ap-northeast-1",
            "eu-central-1",
            "eu-south-1",
            "eu-west-1",
            "eu-west-2",
            "us-east-1",
        ]:
            pytest.skip()
        ec2_client.create_key_pair(KeyName="testkey")  # TODO: cleanup

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template30.yaml"),
            parameters={"KeyName": "testkey"},
        )

        def get_instance_id():
            resources = cfn_client.list_stack_resources(StackName=stack.stack_name)[
                "StackResourceSummaries"
            ]
            instances = [res for res in resources if res["ResourceType"] == "AWS::EC2::Instance"]
            assert len(instances) == 1
            return instances[0]["PhysicalResourceId"]

        instance_id = get_instance_id()
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        assert len(resp["Reservations"][0]["Instances"]) == 1
        assert resp["Reservations"][0]["Instances"][0]["InstanceType"] == "t2.nano"

        deploy_cfn_template(
            stack_name=stack.stack_name,
            template_path=os.path.join(THIS_FOLDER, "templates/template30.yaml"),
            parameters={"InstanceType": "t2.medium"},
        )

        instance_id = get_instance_id()  # get ID of updated instance (may have changed!)
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = resp["Reservations"]
        assert len(reservations) == 1
        assert reservations[0]["Instances"][0]["InstanceType"] == "t2.medium"

    # TODO: purpose?
    def test_cfn_update_different_stack(self, cfn_client, sqs_client, deploy_cfn_template):
        # TODO: make queue name a parameter
        queue_name = f"q-{short_uid()}"
        template1 = TEST_TEMPLATE_27_1 % queue_name
        template2 = TEST_TEMPLATE_27_2 % queue_name

        stack = deploy_cfn_template(template=template1)
        queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]

        stack2 = deploy_cfn_template(
            template=template2, stack_name=stack.stack_name, is_update=True
        )
        queues = sqs_client.list_queues().get("QueueUrls", [])
        assert queue_url in queues
        result = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["All"])
        assert result["Attributes"]["DelaySeconds"] == "5"
        assert stack2.outputs["MessageQueueUrl"] == queue_url

    def test_cfn_event_bus_resource(self, events_client, deploy_cfn_template):
        def _assert(expected_len):
            rs = events_client.list_event_buses()
            event_buses = [eb for eb in rs["EventBuses"] if eb["Name"] == "my-test-bus"]
            assert len(event_buses) == expected_len
            rs = events_client.list_connections()
            connections = [con for con in rs["Connections"] if con["Name"] == "my-test-conn"]
            assert len(connections) == expected_len

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template31.yaml")
        )
        _assert(1)

        stack.destroy()
        _assert(0)

    def test_cfn_statemachine_with_dependencies(self, deploy_cfn_template, stepfunctions_client):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "statemachine_test.json")
        )

        rs = stepfunctions_client.list_state_machines()
        statemachines = [
            sm
            for sm in rs["stateMachines"]
            if "{}-SFSM22S5Y".format(stack.stack_name) in sm["name"]
        ]
        assert len(statemachines) == 1

        stack.destroy()

        rs = stepfunctions_client.list_state_machines()
        statemachines = [
            sm for sm in rs["stateMachines"] if f"{stack.stack_name}-SFSM22S5Y" in sm["name"]
        ]

        assert not statemachines

    def test_cfn_apigateway_rest_api(self, deploy_cfn_template, apigateway_client):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "apigateway.json")
        )

        rs = apigateway_client.get_rest_apis()
        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        assert not apis

        stack.destroy()

        stack_2 = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "apigateway.json"),
            parameters={"Create": "True"},
        )
        rs = apigateway_client.get_rest_apis()
        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        assert len(apis) == 1

        rs = apigateway_client.get_models(restApiId=apis[0]["id"])
        assert len(rs["items"]) == 1

        stack_2.destroy()

        apis = [item for item in rs["items"] if item["name"] == "DemoApi_dev"]
        assert not apis

    def test_cfn_with_exports(self, cfn_client, deploy_cfn_template):
        # fetch initial list of exports
        exports_before = cfn_client.list_exports()["Exports"]

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template32.yaml")
        )
        stack_name = stack.stack_name

        exports = cfn_client.list_exports()["Exports"]
        # TODO: fix assertion, to make tests parallelizable!
        assert len(exports) == len(exports_before) + 6
        export_names = [e["Name"] for e in exports]
        assert f"{stack_name}-FullAccessCentralControlPolicy" in export_names
        assert f"{stack_name}-ReadAccessCentralControlPolicy" in export_names
        assert f"{stack_name}-cc-groups-stream" in export_names
        assert f"{stack_name}-cc-scenes-stream" in export_names
        assert f"{stack_name}-cc-customscenes-stream" in export_names
        assert f"{stack_name}-cc-schedules-stream" in export_names

    # TODO: refactor
    def test_cfn_with_route_table(self, ec2_client, deploy_cfn_template, cfn_client):
        resp = ec2_client.describe_vpcs()
        # TODO: fix assertion, to make tests parallelizable!
        vpcs_before = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "template33.yaml")
        )
        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        assert len(vpcs) == 1

        resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]]}])
        # Each VPC always have 1 default RouteTable
        assert len(resp["RouteTables"]) == 2

        # The 2nd RouteTable was created by cfn template
        route_table_id = resp["RouteTables"][1]["RouteTableId"]
        routes = resp["RouteTables"][1]["Routes"]

        # Each RouteTable has 1 default route
        assert len(routes) == 2

        assert routes[0]["DestinationCidrBlock"] == "100.0.0.0/20"

        # The 2nd Route was created by cfn template
        assert routes[1]["DestinationCidrBlock"] == "0.0.0.0/0"

        exports = cfn_client.list_exports()["Exports"]
        export_values = {ex["Name"]: ex["Value"] for ex in exports}
        assert "publicRoute-identify" in export_values
        assert export_values["publicRoute-identify"] == f"{route_table_id}~0.0.0.0/0"

        stack.destroy()

        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        assert not vpcs

    def test_cfn_with_kms_resources(self, deploy_cfn_template, kms_client):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template34.yaml")
        )

        alias_name = "alias/sample-5302"
        assert stack.outputs.get("KeyAlias") == alias_name

        def _get_matching_aliases():
            aliases = kms_client.list_aliases()["Aliases"]
            return [alias for alias in aliases if alias["AliasName"] == alias_name]

        assert len(_get_matching_aliases()) == 1

        stack.destroy()

        assert not _get_matching_aliases()

    def test_cfn_with_apigateway_resources(self, deploy_cfn_template, apigateway_client):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template35.yaml")
        )
        apis = [
            api
            for api in apigateway_client.get_rest_apis()["items"]
            if api["name"] == "celeste-Gateway-local"
        ]
        assert len(apis) == 1
        api_id = apis[0]["id"]

        resources = [
            res
            for res in apigateway_client.get_resources(restApiId=api_id)["items"]
            if res.get("pathPart") == "account"
        ]

        assert len(resources) == 1

        # assert request parameter is present in resource method
        assert resources[0]["resourceMethods"]["POST"]["requestParameters"] == {
            "method.request.path.account": True
        }
        models = [
            model
            for model in apigateway_client.get_models(restApiId=api_id)["items"]
            if stack.stack_name in model["name"]
        ]

        assert len(models) == 2

        stack.destroy()

        apis = [
            api
            for api in apigateway_client.get_rest_apis()["items"]
            if api["name"] == "celeste-Gateway-local"
        ]
        assert not apis

    def test_dynamodb_stream_response_with_cf(self, dynamodb_client, deploy_cfn_template):
        template = TEST_TEMPLATE_28 % "EventTable"
        deploy_cfn_template(template=template)

        response = dynamodb_client.describe_kinesis_streaming_destination(TableName="EventTable")

        assert response.get("TableName") == "EventTable"
        assert len(response.get("KinesisDataStreamDestinations")) == 1
        assert "StreamArn" in response.get("KinesisDataStreamDestinations")[0]

    # TODO: evaluate (can we drop this?)
    def test_updating_stack_with_iam_role(self, deploy_cfn_template, iam_client, lambda_client):

        # Initialization
        lambda_role_name = f"lambda-role-{short_uid()}"
        lambda_function_name = f"lambda-function-{short_uid()}"

        template = json.loads(load_file(os.path.join(THIS_FOLDER, "templates/template7.json")))

        template["Resources"]["LambdaExecutionRole"]["Properties"]["RoleName"] = lambda_role_name
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name

        # Create stack and wait for 'CREATE_COMPLETE' status of the stack
        stack = deploy_cfn_template(template=json.dumps(template))

        # Checking required values for Lambda function and IAM Role
        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )
        list_roles = list_all_resources(
            lambda kwargs: iam_client.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name
        ]
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name]

        assert len(new_function) == 1
        assert lambda_role_name in new_function[0].get("Role")

        assert len(new_role) == 1

        # Generate new names for lambda and IAM Role
        lambda_role_name_new = f"lambda-role-new-{short_uid()}"
        lambda_function_name_new = f"lambda-function-new-{short_uid()}"

        template["Resources"]["LambdaExecutionRole"]["Properties"][
            "RoleName"
        ] = lambda_role_name_new
        template["Resources"]["LambdaFunction1"]["Properties"][
            "FunctionName"
        ] = lambda_function_name_new

        # Update stack and wait for 'UPDATE_COMPLETE' status of the stack
        deploy_cfn_template(
            is_update=True, template=json.dumps(template), stack_name=stack.stack_name
        )

        # Checking new required values for Lambda function and IAM Role

        list_functions = list_all_resources(
            lambda kwargs: lambda_client.list_functions(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Functions",
        )

        list_roles = list_all_resources(
            lambda kwargs: iam_client.list_roles(**kwargs),
            last_token_attr_name="nextToken",
            list_attr_name="Roles",
        )

        new_function = [
            function
            for function in list_functions
            if function.get("FunctionName") == lambda_function_name_new
        ]
        assert len(new_function) == 1
        assert lambda_role_name_new in new_function[0].get("Role")
        new_role = [role for role in list_roles if role.get("RoleName") == lambda_role_name_new]
        assert len(new_role) == 1

    def test_cfn_with_multiple_route_tables(self, ec2_client, deploy_cfn_template):
        resp = ec2_client.describe_vpcs()
        # TODO: remove/change assertion, to make tests parallelizable!
        vpcs_before = [vpc["VpcId"] for vpc in resp["Vpcs"]]

        deploy_cfn_template(template_path=os.path.join(THIS_FOLDER, "templates/template36.yaml"))

        resp = ec2_client.describe_vpcs()
        vpcs = [vpc["VpcId"] for vpc in resp["Vpcs"] if vpc["VpcId"] not in vpcs_before]
        assert len(vpcs) == 1

        resp = ec2_client.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]]}])
        # CloudFormation will create more than one route table 2 in template + default
        assert len(resp["RouteTables"]) == 3

    def test_cfn_with_multiple_route_table_associations(self, ec2_client, deploy_cfn_template):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates/template37.yaml")
        )
        route_table_id = stack.outputs["RouteTable"]
        route_table = ec2_client.describe_route_tables(
            Filters=[{"Name": "route-table-id", "Values": [route_table_id]}]
        )["RouteTables"][0]

        # CloudFormation will create more than one route table 2 in template + default
        assert len(route_table["Associations"]) == 3

        # assert subnet attributes are present
        vpc_id = stack.outputs["VpcId"]
        response = ec2_client.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
        subnets = response["Subnets"]
        subnet1 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.0.0/24"][0]
        subnet2 = [sub for sub in subnets if sub["CidrBlock"] == "100.0.2.0/24"][0]
        assert subnet1["AssignIpv6AddressOnCreation"] is True
        assert subnet1["EnableDns64"] is True
        assert subnet1["MapPublicIpOnLaunch"] is True
        assert subnet2["PrivateDnsNameOptionsOnLaunch"]["HostnameType"] == "ip-name"

    def test_resolve_transitive_placeholders_in_strings(self, sqs_client, deploy_cfn_template):
        queue_name = f"q-{short_uid()}"
        stack_name = f"stack-{short_uid()}"
        deploy_cfn_template(stack_name=stack_name, template=TEST_TEMPLATE_29 % queue_name)

        tags = sqs_client.list_queue_tags(QueueUrl=aws_stack.get_sqs_queue_url(queue_name))
        test_tag = tags["Tags"]["test"]
        assert test_tag == aws_stack.ssm_parameter_arn("cdk-bootstrap/q123/version")

    def test_default_parameters_kinesis(self, deploy_cfn_template, kinesis_client):
        stack = deploy_cfn_template(
            template_path=os.path.join(THIS_FOLDER, "templates", "kinesis_default.yaml")
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


# Note: DO NOT ADD TEST CASES HERE
#       Add new tests in a corresponding file in the tests/integration/cloudformation directory
