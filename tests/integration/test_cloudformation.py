import os
import json
import time
import unittest

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file, retry, short_uid, to_str
from localstack.utils.cloudformation import template_deployer
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_TEMPLATE_1 = os.path.join(THIS_FOLDER, 'templates', 'template1.yaml')
TEST_TEMPLATE_2 = os.path.join(THIS_FOLDER, 'templates', 'template2.yaml')

TEST_TEMPLATE_3 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
""" % short_uid()

TEST_TEMPLATE_4 = """
AWSTemplateFormatVersion: 2010-09-09
Transform: AWS::Serverless-2016-10-31
Parameters:
  LambdaRuntime:
    Type: String
    Default: python3.6
Resources:
  MyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: test-role-123
      AssumeRolePolicyDocument: {}
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: %s
      Handler: index.handler
      Role: !GetAtt 'MyRole.Arn'
      Runtime:
        Ref: LambdaRuntime
      InlineCode: |
        def handler(event, context):
            return {'hello': 'world'}
"""

TEST_TEMPLATE_5 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  LocalParam:
    Description: Local stack parameter (passed from parent stack)
    Type: String
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub 'test-${LocalParam}'
"""

TEST_ARTIFACTS_BUCKET = 'cf-artifacts'
TEST_ARTIFACTS_PATH = 'stack.yaml'

TEST_TEMPLATE_6 = """
AWSTemplateFormatVersion: 2010-09-09
Parameters:
  GlobalParam:
    Description: Global stack parameter
    Type: String
Resources:
  NestedStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: http://localhost:4572/%s/%s
      Parameters:
        LocalParam: !Ref GlobalParam
""" % (TEST_ARTIFACTS_BUCKET, TEST_ARTIFACTS_PATH)

TEST_TEMPLATE_7 = {
    'AWSTemplateFormatVersion': '2010-09-09',
    'Description': 'Template for AWS::AWS::Function.',
    'Resources': {
        'LambdaFunction1': {
            'Type': 'AWS::Lambda::Function',
            'Properties': {
                'Code': {
                    'ZipFile': 'file.zip'
                },
                'Runtime': 'nodejs12.x',
                'Handler': 'index.handler',
                'Role': {
                    'Fn::GetAtt': ['LambdaExecutionRole', 'Arn']
                },
                'Timeout': 300
            }
        },
        'LambdaExecutionRole': {
            'Type': 'AWS::IAM::Role',
            'Properties': {
                'RoleName': '',
                'AssumeRolePolicyDocument': {
                    'Version': '2012-10-17',
                    'Statement': [
                        {
                            'Action': 'sts:AssumeRole',
                            'Principal': {'Service': 'lambda.amazonaws.com'}
                        }
                    ]
                }
            }
        }
    }
}

TEST_TEMPLATE_8 = {
    'AWSTemplateFormatVersion': '2010-09-09',
    'Description': 'Template for AWS::AWS::Function.',
    'Resources': {
        'S3Bucket': {
            'Type': 'AWS::S3::Bucket',
            'Properties': {
                'BucketName': ''
            }
        },
        'S3BucketPolicy': {
            'Type': 'AWS::S3::BucketPolicy',
            'Properties': {
                'Bucket': {
                    'Ref': 'S3Bucket'
                },
                'PolicyDocument': {
                    'Statement': [
                        {
                            'Effect': 'Allow',
                            'Action': [
                                's3:GetObject',
                                's3:PutObject'
                            ],
                            'Resource': ['*']
                        }
                    ]
                }
            }
        }
    }
}

TEST_TEMPLATE_9 = """
Parameters:
  FeatureBranch:
    Type: String
    Default: false
    AllowedValues: ["true", "false"]
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
""" % TEST_AWS_ACCOUNT_ID

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
    Value: !GetAtt "MyElasticsearchDomain.DomainEndpoint"

  MyElasticsearchArn:
    Value: !GetAtt "MyElasticsearchDomain.Arn"

  MyElasticsearchDomainArn:
    Value: !GetAtt "MyElasticsearchDomain.DomainArn"
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
  SQSQueue:
    Type: 'AWS::SQS::Queue'
    Properties:
        QueueName: %s
        ContentBasedDeduplication: "false"
        FifoQueue: "true"
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
      BucketName: '%s'
"""

TEST_DEPLOY_BODY_1 = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  # IAM role for running the step function
  ExecutionRole:
    Type: "AWS::IAM::Role"
    Properties:
      RoleName: %s
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
        - Effect: "Allow"
          Principal:
            Service: !Sub states.${AWS::Region}.amazonaws.com
          Action: "sts:AssumeRole"
      Policies:
      - PolicyName: StatesExecutionPolicy
        PolicyDocument:
          Version: "2012-10-17"
          Statement:
          - Effect: Allow
            Action: "lambda:InvokeFunction"
            Resource: "*"
"""

TEST_DEPLOY_BODY_2 = """
AWSTemplateFormatVersion: '2010-09-09'
Description:
  SNS Topics for stuff

Parameters:
  CompanyName:
    Type: String
    Description: 'Customer/Company name, commonly known-by name'
    AllowedPattern: '[A-Za-z0-9-]{5,}'
    ConstraintDescription: 'String must be 5 or more characters, letters, numbers and -'

  MyEmail1:
    Type: String
    Description: Email address for stuff
    Default: ""

  MyEmail2:
    Type: String
    Description: Email address for stuff
    Default: ""

Conditions:
  HasMyEmail1: !Not [!Equals [!Ref MyEmail1, '']]
  HasMyEmail2: !Not [!Equals [!Ref MyEmail2, '']]

  SetupMy: !Or
                - Condition: HasMyEmail1
                - Condition: HasMyEmail2

Resources:
  MyTopic:
    Condition: SetupMy
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: !Sub "${CompanyName} AWS MyTopic"
      Subscription:
        - !If
          - HasMyEmail1
          -
            Endpoint: !Ref MyEmail1
            Protocol: email
          - !Ref AWS::NoValue
        - !If
          - HasMyEmail2
          -
            Endpoint: !Ref MyEmail2
            Protocol: email
          - !Ref AWS::NoValue

Outputs:
  StackName:
    Description: 'Stack name'
    Value: !Sub '${AWS::StackName}'
    Export:
      Name: !Sub '${AWS::StackName}-StackName'

  MyTopic:
    Condition: SetupMy
    Description: 'My arn'
    Value: !Ref MyTopic
    Export:
      Name: !Sub '${AWS::StackName}-MyTopicArn'

  MyTopicName:
    Condition: SetupMy
    Description: 'My Name'
    Value: !GetAtt MyTopic.TopicName
    Export:
      Name: !Sub '${AWS::StackName}-MyTopicName'
"""

TEST_DEPLOY_BODY_3 = """
AWSTemplateFormatVersion: '2010-09-09'
Description: DynamoDB resource stack creation using Amplify CLI
Parameters:
  partitionKeyName:
    Type: String
    Default: startTime
  partitionKeyType:
    Type: String
    Default: String
  env:
    Type: String
    Default: Staging
  sortKeyName:
    Type: String
    Default: name
  sortKeyType:
    Type: String
    Default: String
  tableName:
    Type: String
    Default: ddb1
Conditions:
  ShouldNotCreateEnvResources:
    Fn::Equals:
    - Ref: env
    - NONE
Resources:
  DynamoDBTable:
    Type: AWS::DynamoDB::Table
    Properties:
      TableName:
        Fn::If:
          - ShouldNotCreateEnvResources
          - Ref: tableName
          - Fn::Join:
              - ''
              - - Ref: tableName
                - "-"
                - Ref: env
      AttributeDefinitions:
      - AttributeName: name
        AttributeType: S
      - AttributeName: startTime
        AttributeType: S
      - AttributeName: externalUserID
        AttributeType: S
      KeySchema:
      - AttributeName: name
        KeyType: HASH
      - AttributeName: startTime
        KeyType: RANGE
      ProvisionedThroughput:
        ReadCapacityUnits: 5
        WriteCapacityUnits: 5
      StreamSpecification:
        StreamViewType: NEW_IMAGE
      GlobalSecondaryIndexes:
      - IndexName: byUser
        KeySchema:
        - AttributeName: externalUserID
          KeyType: HASH
        - AttributeName: startTime
          KeyType: RANGE
        Projection:
          ProjectionType: ALL
        ProvisionedThroughput:
          ReadCapacityUnits: 5
          WriteCapacityUnits: 5
Outputs:
  Name:
    Value:
      Ref: DynamoDBTable
  Arn:
    Value:
      Fn::GetAtt:
      - DynamoDBTable
      - Arn
  StreamArn:
    Value:
      Fn::GetAtt:
      - DynamoDBTable
      - StreamArn
  PartitionKeyName:
    Value:
      Ref: partitionKeyName
  PartitionKeyType:
    Value:
      Ref: partitionKeyType
  SortKeyName:
    Value:
      Ref: sortKeyName
  SortKeyType:
    Value:
      Ref: sortKeyType
  Region:
    Value:
      Ref: AWS::Region
"""

TEST_TEMPLATE_19 = """
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
""" % TEST_AWS_ACCOUNT_ID


def bucket_exists(name):
    s3_client = aws_stack.connect_to_service('s3')
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        if bucket['Name'] == name:
            return True


def queue_exists(name):
    sqs_client = aws_stack.connect_to_service('sqs')
    queues = sqs_client.list_queues()
    try:
        url = name if '://' in name else aws_stack.get_sqs_queue_url(name)
    except Exception:
        return False
    for queue_url in queues['QueueUrls']:
        if queue_url == url:
            return queue_url


def topic_exists(name):
    sns_client = aws_stack.connect_to_service('sns')
    topics = sns_client.list_topics()
    for topic in topics['Topics']:
        topic_arn = topic['TopicArn']
        if topic_arn.endswith(':%s' % name):
            return topic_arn


def queue_url_exists(queue_url):
    sqs_client = aws_stack.connect_to_service('sqs')
    queues = sqs_client.list_queues()
    return queue_url in queues['QueueUrls']


def stream_exists(name):
    kinesis_client = aws_stack.connect_to_service('kinesis')
    streams = kinesis_client.list_streams()
    return name in streams['StreamNames']


def ssm_param_exists(name):
    client = aws_stack.connect_to_service('ssm')
    params = client.describe_parameters(Filters=[{'Key': 'Name', 'Values': [name]}])['Parameters']
    param = (params or [{}])[0]
    return param.get('Name') == name and param


def get_stack_details(stack_name):
    cloudformation = aws_stack.connect_to_service('cloudformation')
    stacks = cloudformation.describe_stacks(StackName=stack_name)
    for stack in stacks['Stacks']:
        if stack['StackName'] == stack_name:
            return stack


def describe_stack_resource(stack_name, resource_logical_id):
    cloudformation = aws_stack.connect_to_service('cloudformation')
    response = cloudformation.describe_stack_resources(StackName=stack_name)
    for resource in response['StackResources']:
        if resource['LogicalResourceId'] == resource_logical_id:
            return resource


def list_stack_resources(stack_name):
    cloudformation = aws_stack.connect_to_service('cloudformation')
    response = cloudformation.list_stack_resources(StackName=stack_name)
    return response['StackResourceSummaries']


def get_queue_urls():
    sqs = aws_stack.connect_to_service('sqs')
    response = sqs.list_queues()
    return response['QueueUrls']


def get_topic_arns():
    sqs = aws_stack.connect_to_service('sns')
    response = sqs.list_topics()
    return [t['TopicArn'] for t in response['Topics']]


def _deploy_stack(stack_name, template_body):
    cfn = aws_stack.connect_to_service('cloudformation')
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    # wait for deployment to finish
    return _await_stack_completion(stack_name)


def _await_stack_status(stack_name, expected_status, retries=3, sleep=2):
    def check_stack():
        stack = get_stack_details(stack_name)
        assert stack['StackStatus'] == expected_status
        return stack
    return retry(check_stack, retries, sleep)


def _await_stack_completion(stack_name, retries=3, sleep=2):
    return _await_stack_status(stack_name, 'CREATE_COMPLETE', retries=retries, sleep=sleep)


class CloudFormationTest(unittest.TestCase):
    def test_create_delete_stack(self):
        cloudformation = aws_stack.connect_to_resource('cloudformation')
        cf_client = aws_stack.connect_to_service('cloudformation')
        s3 = aws_stack.connect_to_service('s3')
        sns = aws_stack.connect_to_service('sns')
        sqs = aws_stack.connect_to_service('sqs')
        apigateway = aws_stack.connect_to_service('apigateway')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_1))

        # deploy template
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=template)

        _await_stack_completion(stack_name)

        # assert that resources have been created
        assert bucket_exists('cf-test-bucket-1')
        queue_url = queue_exists('cf-test-queue-1')
        assert queue_url
        topic_arn = topic_exists('%s-test-topic-1-1' % stack_name)
        assert topic_arn
        assert stream_exists('cf-test-stream-1')
        resource = describe_stack_resource(stack_name, 'SQSQueueNoNameProperty')
        assert queue_exists(resource['PhysicalResourceId'])
        assert ssm_param_exists('cf-test-param-1')

        # assert that tags have been created
        tags = s3.get_bucket_tagging(Bucket='cf-test-bucket-1')['TagSet']
        self.assertEqual(tags, [{'Key': 'foobar', 'Value': aws_stack.get_sqs_queue_url('cf-test-queue-1')}])
        tags = sns.list_tags_for_resource(ResourceArn=topic_arn)['Tags']
        self.assertEqual(tags, [
            {'Key': 'foo', 'Value': 'cf-test-bucket-1'},
            {'Key': 'bar', 'Value': aws_stack.s3_bucket_arn('cf-test-bucket-1')}
        ])
        queue_tags = sqs.list_queue_tags(QueueUrl=queue_url)
        self.assertIn('Tags', queue_tags)
        self.assertEqual(queue_tags['Tags'], {'key1': 'value1', 'key2': 'value2'})

        # assert that bucket notifications have been created
        notifications = s3.get_bucket_notification_configuration(Bucket='cf-test-bucket-1')
        self.assertIn('QueueConfigurations', notifications)
        self.assertIn('LambdaFunctionConfigurations', notifications)
        self.assertEqual(notifications['QueueConfigurations'][0]['QueueArn'], 'aws:arn:sqs:test:testqueue')
        self.assertEqual(notifications['QueueConfigurations'][0]['Events'], ['s3:ObjectDeleted:*'])
        self.assertEqual(
            notifications['LambdaFunctionConfigurations'][0]['LambdaFunctionArn'],
            'aws:arn:lambda:test:testfunc'
        )
        self.assertEqual(notifications['LambdaFunctionConfigurations'][0]['Events'], ['s3:ObjectCreated:*'])

        # assert that subscriptions have been created
        subs = sns.list_subscriptions()['Subscriptions']
        subs = [s for s in subs if (':%s:cf-test-queue-1' % TEST_AWS_ACCOUNT_ID) in s['Endpoint']]
        self.assertEqual(len(subs), 1)
        self.assertIn(':%s:%s-test-topic-1-1' % (TEST_AWS_ACCOUNT_ID, stack_name), subs[0]['TopicArn'])
        # assert that subscription attributes are added properly
        attrs = sns.get_subscription_attributes(SubscriptionArn=subs[0]['SubscriptionArn'])['Attributes']
        self.assertEqual(attrs, {'Endpoint': subs[0]['Endpoint'], 'Protocol': 'sqs',
            'SubscriptionArn': subs[0]['SubscriptionArn'], 'TopicArn': subs[0]['TopicArn'],
            'FilterPolicy': json.dumps({'eventType': ['created']})})

        # assert that Gateway responses have been created
        test_api_name = 'test-api'
        api = [a for a in apigateway.get_rest_apis()['items'] if a['name'] == test_api_name][0]
        responses = apigateway.get_gateway_responses(restApiId=api['id'])['items']
        self.assertEqual(len(responses), 2)
        types = [r['responseType'] for r in responses]
        self.assertEqual(set(types), set(['UNAUTHORIZED', 'DEFAULT_5XX']))

        # delete the stack
        cf_client.delete_stack(StackName=stack_name)

        # assert that resources have been deleted
        assert not bucket_exists('cf-test-bucket-1')
        assert not queue_exists('cf-test-queue-1')
        assert not topic_exists('%s-test-topic-1-1' % stack_name)
        retry(lambda: self.assertFalse(stream_exists('cf-test-stream-1')))

    def test_list_stack_events(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        response = cloudformation.describe_stack_events()
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_validate_template(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_1))
        response = cloudformation.validate_template(TemplateBody=template)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_validate_invalid_json_template_should_fail(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        invalid_json = '{"this is invalid JSON"="bobbins"}'

        try:
            cloudformation.validate_template(TemplateBody=invalid_json)
            self.fail('Should raise ValidationError')
        except (ClientError, ResponseParserError) as err:
            if isinstance(err, ClientError):
                self.assertEqual(err.response['ResponseMetadata']['HTTPStatusCode'], 400)
                self.assertEqual(err.response['Error']['Message'], 'Template Validation Error')

    def test_list_stack_resources_returns_queue_urls(self):
        cloudformation = aws_stack.connect_to_resource('cloudformation')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_2))
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=template)

        details = _await_stack_completion(stack_name)

        stack_summaries = list_stack_resources(stack_name)
        queue_urls = get_queue_urls()
        topic_arns = get_topic_arns()

        stack_queues = [r for r in stack_summaries if r['ResourceType'] == 'AWS::SQS::Queue']
        for resource in stack_queues:
            self.assertIn(resource['PhysicalResourceId'], queue_urls)

        stack_topics = [r for r in stack_summaries if r['ResourceType'] == 'AWS::SNS::Topic']
        for resource in stack_topics:
            self.assertIn(resource['PhysicalResourceId'], topic_arns)

        # assert that stack outputs are returned properly
        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0]['ExportName'], 'SQSQueue1-URL')

    def test_create_change_set(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')

        # deploy template
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_3)

        # create change set with the same template (no changes)
        response = cloudformation.create_change_set(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_3,
            ChangeSetName='nochanges'
        )
        self.assertIn(':%s:changeSet/nochanges/' % TEST_AWS_ACCOUNT_ID, response['Id'])
        self.assertIn(':%s:stack/' % TEST_AWS_ACCOUNT_ID, response['StackId'])

    def test_sam_template(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        awslambda = aws_stack.connect_to_service('lambda')

        # deploy template
        stack_name = 'stack-%s' % short_uid()
        func_name = 'test-%s' % short_uid()
        template = TEST_TEMPLATE_4 % func_name
        cloudformation.create_stack(StackName=stack_name, TemplateBody=template)

        # run Lambda test invocation
        result = awslambda.invoke(FunctionName=func_name)
        result = json.loads(to_str(result['Payload'].read()))
        self.assertEqual(result, {'hello': 'world'})

        # delete lambda function
        awslambda.delete_function(FunctionName=func_name)

    def test_nested_stack(self):
        s3 = aws_stack.connect_to_service('s3')
        cloudformation = aws_stack.connect_to_service('cloudformation')

        # upload template to S3
        s3.create_bucket(Bucket=TEST_ARTIFACTS_BUCKET, ACL='public-read')
        s3.put_object(Bucket=TEST_ARTIFACTS_BUCKET, Key=TEST_ARTIFACTS_PATH, Body=TEST_TEMPLATE_5)

        # deploy template
        buckets_before = len(s3.list_buckets()['Buckets'])
        stack_name = 'stack-%s' % short_uid()
        param_value = short_uid()
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_6,
            Parameters=[{'ParameterKey': 'GlobalParam', 'ParameterValue': param_value}]
        )

        # assert that nested resources have been created
        buckets_after = s3.list_buckets()['Buckets']
        num_buckets_after = len(buckets_after)
        self.assertEqual(num_buckets_after, buckets_before + 1)
        bucket_names = [b['Name'] for b in buckets_after]
        self.assertIn('test-%s' % param_value, bucket_names)

        # delete the stack
        cloudformation.delete_stack(StackName=stack_name)

    def test_create_cfn_lambda_without_function_name(self):
        lambda_client = aws_stack.connect_to_service('lambda')
        cloudformation = aws_stack.connect_to_service('cloudformation')

        rs = lambda_client.list_functions()
        # Number of lambdas before of stack creation
        lambdas_before = len(rs['Functions'])

        stack_name = 'stack-%s' % short_uid()
        lambda_role_name = 'lambda-role-%s' % short_uid()
        TEST_TEMPLATE_7['Resources']['LambdaExecutionRole']['Properties']['RoleName'] = lambda_role_name
        rs = cloudformation.create_stack(StackName=stack_name, TemplateBody=json.dumps(TEST_TEMPLATE_7))

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('StackId', rs)
        self.assertIn(stack_name, rs['StackId'])

        _await_stack_completion(stack_name)

        rs = lambda_client.list_functions()

        # There is 1 new lambda function
        self.assertEqual(lambdas_before + 1, len(rs['Functions']))

        # delete the stack
        cloudformation.delete_stack(StackName=stack_name)

    def test_deploy_stack_change_set(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()
        bucket_name = 'bucket-%s' % short_uid()

        try:
            cloudformation.describe_stacks(
                StackName=stack_name
            )
            self.fail('This call should not be successful as the stack does not exist')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'ValidationError')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_CHANGE_SET_BODY % bucket_name,
            Parameters=[
                {
                    'ParameterKey': 'EnvironmentType',
                    'ParameterValue': 'stage'
                }
            ],
            Capabilities=['CAPABILITY_IAM'],
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        change_set_id = rs['Id']

        rs = cloudformation.describe_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_id
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ChangeSetName'], change_set_name)
        self.assertEqual(rs['ChangeSetId'], change_set_id)
        self.assertEqual(rs['Status'], 'CREATE_COMPLETE')

        rs = cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = cloudformation.describe_stacks(
            StackName=stack_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        stack = rs['Stacks'][0]
        parameters = stack['Parameters']

        self.assertEqual(stack['StackName'], stack_name)
        self.assertEqual(parameters[0]['ParameterKey'], 'EnvironmentType')
        self.assertEqual(parameters[0]['ParameterValue'], 'stage')

        self.assertTrue(bucket_exists(bucket_name))

        # clean up
        cloudformation.delete_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        cloudformation.delete_stack(
            StackName=stack_name
        )

    def test_deploy_stack_with_iam_role(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()
        role_name = 'role-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        try:
            cloudformation.describe_stacks(
                StackName=stack_name
            )
            self.fail('This call should not be successful as the stack does not exist')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'ValidationError')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_DEPLOY_BODY_1 % role_name
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        change_set_id = rs['Id']

        rs = cloudformation.describe_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_id
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ChangeSetName'], change_set_name)
        self.assertEqual(rs['ChangeSetId'], change_set_id)
        self.assertEqual(rs['Status'], 'CREATE_COMPLETE')

        rs = cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = cloudformation.describe_stacks(
            StackName=stack_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        stack = rs['Stacks'][0]
        self.assertEqual(stack['StackName'], stack_name)

        iam_client = aws_stack.connect_to_service('iam')
        rs = iam_client.list_roles(
            PathPrefix=role_name
        )

        self.assertEqual(len(rs['Roles']), 1)
        self.assertEqual(rs['Roles'][0]['RoleName'], role_name)

        rs = iam_client.list_role_policies(
            RoleName=role_name
        )

        iam_client.delete_role_policy(
            RoleName=role_name,
            PolicyName=rs['PolicyNames'][0]
        )

        # clean up
        cloudformation.delete_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        cloudformation.delete_stack(
            StackName=stack_name
        )

        rs = iam_client.list_roles(
            PathPrefix=role_name
        )
        self.assertEqual(len(rs['Roles']), 0)

    def test_deploy_stack_with_sns_topic(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_DEPLOY_BODY_2,
            Parameters=[
                {
                    'ParameterKey': 'CompanyName',
                    'ParameterValue': 'MyCompany'
                },
                {
                    'ParameterKey': 'MyEmail1',
                    'ParameterValue': 'my@email.com'
                }
            ]
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = cloudformation.describe_stacks(
            StackName=stack_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        stack = rs['Stacks'][0]
        self.assertEqual(stack['StackName'], stack_name)
        outputs = stack['Outputs']
        self.assertEqual(len(outputs), 3)

        topic_arn = None
        for op in outputs:
            if op['OutputKey'] == 'MyTopic':
                topic_arn = op['OutputValue']

        sns_client = aws_stack.connect_to_service('sns')
        rs = sns_client.list_topics()

        # Topic resource created
        topics = [tp for tp in rs['Topics'] if tp['TopicArn'] == topic_arn]
        self.assertEqual(len(topics), 1)

        # clean up
        cloudformation.delete_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        cloudformation.delete_stack(
            StackName=stack_name
        )

        # Topic resource removed
        rs = sns_client.list_topics()
        topics = [tp for tp in rs['Topics'] if tp['TopicArn'] == topic_arn]
        self.assertEqual(len(topics), 0)

    def test_deploy_stack_with_dynamodb_table(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()
        env = 'Staging'
        ddb_table_name_prefix = 'ddb-table-%s' % short_uid()
        ddb_table_name = '{}-{}'.format(ddb_table_name_prefix, env)

        cloudformation = aws_stack.connect_to_service('cloudformation')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_DEPLOY_BODY_3,
            Parameters=[
                {
                    'ParameterKey': 'tableName',
                    'ParameterValue': ddb_table_name_prefix
                },
                {
                    'ParameterKey': 'env',
                    'ParameterValue': env
                }
            ]
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        change_set_id = rs['Id']

        rs = cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        rs = cloudformation.describe_stacks(
            StackName=stack_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        stacks = [stack for stack in rs['Stacks'] if stack['StackName'] == stack_name]
        self.assertEqual(len(stacks), 1)
        self.assertEqual(stacks[0]['ChangeSetId'], change_set_id)

        outputs = {
            output['OutputKey']: output['OutputValue']
            for output in stacks[0]['Outputs']
        }
        self.assertIn('Arn', outputs)
        self.assertEqual(outputs['Arn'], 'arn:aws:dynamodb:{}:{}:table/{}'.format(
            aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, ddb_table_name))

        self.assertIn('Name', outputs)
        self.assertEqual(outputs['Name'], ddb_table_name)

        ddb_client = aws_stack.connect_to_service('dynamodb')
        rs = ddb_client.list_tables()
        self.assertIn(ddb_table_name, rs['TableNames'])

        # clean up
        cloudformation.delete_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        cloudformation.delete_stack(
            StackName=stack_name
        )
        rs = ddb_client.list_tables()
        self.assertNotIn(ddb_table_name, rs['TableNames'])

    def test_cfn_handle_s3_bucket_resources(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 's3-bucket-%s' % short_uid()

        TEST_TEMPLATE_8['Resources']['S3Bucket']['Properties']['BucketName'] = bucket_name

        self.assertFalse(bucket_exists(bucket_name))

        s3 = aws_stack.connect_to_service('s3')
        cfn = aws_stack.connect_to_service('cloudformation')

        _deploy_stack(stack_name=stack_name, template_body=json.dumps(TEST_TEMPLATE_8))

        self.assertTrue(bucket_exists(bucket_name))

        rs = s3.get_bucket_policy(
            Bucket=bucket_name
        )

        self.assertIn('Policy', rs)
        self.assertEqual(json.loads(rs['Policy']),
                         TEST_TEMPLATE_8['Resources']['S3BucketPolicy']['Properties']['PolicyDocument'])

        cfn.delete_stack(StackName=stack_name)

        self.assertFalse(bucket_exists(bucket_name))

        try:
            s3.get_bucket_policy(
                Bucket=bucket_name
            )
            self.fail('This call should not be successful as the bucket policy was deleted')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'NoSuchBucket')

        rs = cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(TEST_TEMPLATE_8))
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        cfn.delete_stack(StackName=stack_name)

    def test_cfn_handle_log_group_resource(self):
        stack_name = 'stack-%s' % short_uid()
        log_group_prefix = '/aws/lambda/AWS_DUB_LAM_10000000'

        cfn = aws_stack.connect_to_service('cloudformation')
        logs_client = aws_stack.connect_to_service('logs')

        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_9)

        rs = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_prefix
        )

        self.assertEqual(len(rs['logGroups']), 1)
        self.assertEqual(rs['logGroups'][0]['logGroupName'],
                         '/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev')

        cfn.delete_stack(StackName=stack_name)

        rs = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_prefix
        )

        self.assertEqual(len(rs['logGroups']), 0)

    def test_cfn_handle_elasticsearch_domain(self):
        stack_name = 'stack-%s' % short_uid()
        domain_name = 'es-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        es_client = aws_stack.connect_to_service('es')

        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_10,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )

        details = _await_stack_completion(stack_name)
        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 3)

        rs = es_client.describe_elasticsearch_domain(
            DomainName=domain_name
        )
        status = rs['DomainStatus']
        self.assertEqual(domain_name, status['DomainName'])

        tags = es_client.list_tags(ARN=status['ARN'])['TagList']
        self.assertEqual([{'Key': 'k1', 'Value': 'v1'}, {'Key': 'k2', 'Value': 'v2'}], tags)

        for o in outputs:
            if o['OutputKey'] in ['MyElasticsearchArn', 'MyElasticsearchDomainArn']:
                self.assertEqual(o['OutputValue'], status['ARN'])
            elif o['OutputKey'] == 'MyElasticsearchDomainEndpoint':
                self.assertEqual(o['OutputValue'], status['Endpoint'])
            else:
                self.fail('Unexpected output: %s' % o)
        cloudformation.delete_stack(StackName=stack_name)

    def test_cfn_handle_secretsmanager_secret(self):
        stack_name = 'stack-%s' % short_uid()
        secret_name = 'secret-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        params = [{'ParameterKey': 'SecretName', 'ParameterValue': secret_name}]
        cloudformation.create_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_11, Parameters=params)

        _await_stack_completion(stack_name)

        secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

        rs = secretsmanager_client.describe_secret(
            SecretId=secret_name
        )

        self.assertEqual(secret_name, rs['Name'])
        self.assertNotIn('DeletedDate', rs)
        cloudformation.delete_stack(StackName=stack_name)

        rs = secretsmanager_client.describe_secret(
            SecretId=secret_name
        )
        self.assertIn('DeletedDate', rs)

    def test_cfn_handle_kinesis_firehose_resources(self):
        stack_name = 'stack-%s' % short_uid()
        kinesis_stream_name = 'kinesis-stream-%s' % short_uid()
        firehose_role_name = 'firehose-role-%s' % short_uid()
        firehose_stream_name = 'firehose-stream-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_12 % firehose_role_name,
            Parameters=[
                {'ParameterKey': 'KinesisStreamName', 'ParameterValue': kinesis_stream_name},
                {'ParameterKey': 'DeliveryStreamName', 'ParameterValue': firehose_stream_name}
            ]
        )

        details = _await_stack_completion(stack_name)

        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 1)

        kinesis_client = aws_stack.connect_to_service('kinesis')
        firehose_client = aws_stack.connect_to_service('firehose')

        rs = firehose_client.describe_delivery_stream(
            DeliveryStreamName=firehose_stream_name
        )
        self.assertEqual(outputs[0]['OutputValue'], rs['DeliveryStreamDescription']['DeliveryStreamARN'])
        self.assertEqual(firehose_stream_name, rs['DeliveryStreamDescription']['DeliveryStreamName'])

        rs = kinesis_client.describe_stream(
            StreamName=kinesis_stream_name
        )
        self.assertEqual(rs['StreamDescription']['StreamName'], kinesis_stream_name)

        cloudformation.delete_stack(StackName=stack_name)
        time.sleep(2)

        rs = kinesis_client.list_streams()
        self.assertNotIn(kinesis_stream_name, rs['StreamNames'])

        rs = firehose_client.list_delivery_streams()
        self.assertNotIn(firehose_stream_name, rs['DeliveryStreamNames'])

    def test_cfn_handle_iam_role_resource(self):
        stack_name = 'stack-%s' % short_uid()
        role_name = 'role-%s' % short_uid()
        role_path_prefix = '/role-prefix-%s/' % short_uid()

        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_13 % (role_name, role_path_prefix))

        cfn = aws_stack.connect_to_service('cloudformation')
        iam = aws_stack.connect_to_service('iam')

        rs = iam.list_roles(
            PathPrefix=role_path_prefix
        )

        self.assertEqual(len(rs['Roles']), 1)

        role = rs['Roles'][0]

        self.assertEqual(role['RoleName'], role_name)

        cfn.delete_stack(StackName=stack_name)

        rs = iam.list_roles(
            PathPrefix=role_path_prefix
        )

        self.assertEqual(len(rs['Roles']), 0)

    def test_cfn_handle_iam_role_resource_no_role_name(self):
        cfn = aws_stack.connect_to_service('cloudformation')
        iam = aws_stack.connect_to_service('iam')

        stack_name = 'stack-%s' % short_uid()
        role_path_prefix = '/role-prefix-%s/' % short_uid()

        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_14 % role_path_prefix)

        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(len(rs['Roles']), 1)

        cfn.delete_stack(StackName=stack_name)

        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(len(rs['Roles']), 0)

    def test_cfn_conditional_deployment(self):
        s3 = aws_stack.connect_to_service('s3')

        bucket_id = short_uid()
        template = TEST_TEMPLATE_19.format(id=bucket_id)
        stack_name = 'stack-%s' % short_uid()
        _deploy_stack(stack_name=stack_name, template_body=template)

        buckets = s3.list_buckets()['Buckets']
        dev_bucket = 'cf-dev-%s' % bucket_id
        prd_bucket = 'cf-prd-%s' % bucket_id
        dev_bucket = [b for b in buckets if b['Name'] == dev_bucket]
        prd_bucket = [b for b in buckets if b['Name'] == prd_bucket]

        self.assertFalse(prd_bucket)
        self.assertTrue(dev_bucket)

    def test_cfn_handle_sqs_resource(self):
        stack_name = 'stack-%s' % short_uid()
        queue_name = 'queue-%s.fifo' % short_uid()

        cfn = aws_stack.connect_to_service('cloudformation')
        sqs = aws_stack.connect_to_service('sqs')

        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_15 % queue_name)

        rs = sqs.get_queue_url(QueueName=queue_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        queue_url = rs['QueueUrl']

        rs = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['All']
        )

        attributes = rs['Attributes']

        self.assertIn('ContentBasedDeduplication', attributes)
        self.assertIn('FifoQueue', attributes)
        self.assertEqual(attributes['ContentBasedDeduplication'], 'false')
        self.assertEqual(attributes['FifoQueue'], 'true')

        cfn.delete_stack(StackName=stack_name)

        try:
            sqs.get_queue_url(QueueName=queue_name)
            self.fail('This call should not be successful as the queue was deleted')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'AWS.SimpleQueueService.NonExistentQueue')

    def test_cfn_handle_events_rule(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 'target-%s' % short_uid()
        rule_prefix = 's3-rule-%s' % short_uid()
        rule_name = '%s-%s' % (rule_prefix, short_uid())

        cfn = aws_stack.connect_to_service('cloudformation')
        events = aws_stack.connect_to_service('events')

        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_16 % (bucket_name, rule_name))

        rs = events.list_rules(
            NamePrefix=rule_prefix
        )
        self.assertIn(rule_name, [rule['Name'] for rule in rs['Rules']])

        target_arn = aws_stack.s3_bucket_arn(bucket_name)
        rs = events.list_targets_by_rule(
            Rule=rule_name
        )
        self.assertIn(target_arn, [target['Arn'] for target in rs['Targets']])

        cfn.delete_stack(StackName=stack_name)

        rs = events.list_rules(
            NamePrefix=rule_prefix
        )
        self.assertNotIn(rule_name, [rule['Name'] for rule in rs['Rules']])

    def test_cfn_handle_events_rule_without_name(self):
        events = aws_stack.connect_to_service('events')

        rs = events.list_rules()
        rule_names = [rule['Name'] for rule in rs['Rules']]

        stack_name = 'stack-%s' % short_uid()
        _deploy_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_18 % aws_stack.role_arn('sfn_role'))

        rs = events.list_rules()
        new_rules = [rule for rule in rs['Rules'] if rule['Name'] not in rule_names]
        self.assertEqual(len(new_rules), 1)
        rule = new_rules[0]

        self.assertEqual(rule['ScheduleExpression'], 'cron(0/1 * * * ? *)')

        cfn = aws_stack.connect_to_service('cloudformation')
        cfn.delete_stack(StackName=stack_name)
        time.sleep(1)

        rs = events.list_rules()
        self.assertNotIn(rule['Name'], [r['Name'] for r in rs['Rules']])

    def test_cfn_handle_s3_notification_configuration(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 'target-%s' % short_uid()
        queue_name = 'queue-%s' % short_uid()
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        cfn = aws_stack.connect_to_service('cloudformation')
        s3 = aws_stack.connect_to_service('s3')

        _deploy_stack(
            stack_name=stack_name,
            template_body=TEST_TEMPLATE_17 % (queue_name, bucket_name, queue_arn)
        )

        rs = s3.get_bucket_notification_configuration(
            Bucket=bucket_name
        )
        self.assertIn('QueueConfigurations', rs)
        self.assertEqual(len(rs['QueueConfigurations']), 1)
        self.assertEqual(rs['QueueConfigurations'][0]['QueueArn'], queue_arn)

        cfn.delete_stack(StackName=stack_name)

        rs = s3.get_bucket_notification_configuration(
            Bucket=bucket_name
        )
        self.assertNotIn('QueueConfigurations', rs)

    def test_delete_stack(self):
        domain_name = 'es-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        cloudformation.create_stack(
            StackName='myteststack',
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )

        cloudformation.create_stack(
            StackName='myteststack2',
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )

        cloudformation.delete_stack(StackName='myteststack2')
        cloudformation.delete_stack(StackName='myteststack')
