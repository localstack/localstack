import os
import json
import time
import unittest
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file, retry, short_uid, to_str
from localstack.utils.testutil import create_zip_file
from localstack.utils.aws.aws_stack import await_stack_completion, deploy_cf_stack
from localstack.utils.cloudformation import template_deployer

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))

TEST_TEMPLATE_1 = os.path.join(THIS_FOLDER, 'templates', 'template1.yaml')

TEST_TEMPLATE_2 = os.path.join(THIS_FOLDER, 'templates', 'template2.yaml')

APIGW_INTEGRATION_TEMPLATE = os.path.join(THIS_FOLDER, 'templates', 'apigateway_integration.json')

TEST_VALID_TEMPLATE = os.path.join(THIS_FOLDER, 'templates', 'valid_template.json')

TEST_TEMPLATE_3 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
""" % short_uid()

TEST_TEMPLATE_4 = os.path.join(THIS_FOLDER, 'templates', 'template4.yaml')

TEST_TEMPLATE_5 = os.path.join(THIS_FOLDER, 'templates', 'template5.yaml')

TEST_ARTIFACTS_BUCKET = 'cf-artifacts'
TEST_ARTIFACTS_PATH = 'stack.yaml'

TEST_TEMPLATE_6 = os.path.join(THIS_FOLDER, 'templates', 'template6.yaml')

TEST_TEMPLATE_7 = os.path.join(THIS_FOLDER, 'templates', 'template7.json')

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

TEST_DEPLOY_BODY_1 = os.path.join(THIS_FOLDER, 'templates', 'deploy_template_1.yaml')

TEST_DEPLOY_BODY_2 = os.path.join(THIS_FOLDER, 'templates', 'deploy_template_2.yaml')

TEST_DEPLOY_BODY_3 = os.path.join(THIS_FOLDER, 'templates', 'deploy_template_3.yaml')

TEST_DEPLOY_BODY_4 = os.path.join(THIS_FOLDER, 'templates', 'deploy_template_4.yaml')

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

TEST_TEMPLATE_21 = os.path.join(THIS_FOLDER, 'templates', 'template21.json')

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

TEST_TEMPLATE_23 = os.path.join(THIS_FOLDER, 'templates', 'template23.yaml')

TEST_TEMPLATE_24 = os.path.join(THIS_FOLDER, 'templates', 'template24.yaml')

TEST_TEMPLATE_25 = os.path.join(THIS_FOLDER, 'templates', 'template25.yaml')

TEST_UPDATE_LAMBDA_FUNCTION_TEMPLATE = os.path.join(THIS_FOLDER, 'templates', 'update_lambda_template.json')

SQS_TEMPLATE = os.path.join(THIS_FOLDER, 'templates', 'fifo_queue.json')


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

        await_stack_completion(stack_name)

        # assert that resources have been created
        self.assertTrue(bucket_exists('cf-test-bucket-1'))
        queue_url = queue_exists('cf-test-queue-1')
        self.assertTrue(queue_url)
        topic_arn = topic_exists('%s-test-topic-1-1' % stack_name)
        self.assertTrue(topic_arn)
        self.assertTrue(stream_exists('cf-test-stream-1'))
        resource = describe_stack_resource(stack_name, 'SQSQueueNoNameProperty')
        self.assertTrue(queue_exists(resource['PhysicalResourceId']))
        self.assertTrue(ssm_param_exists('cf-test-param-1'))

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
        self.assertFalse(bucket_exists('cf-test-bucket-1'))
        self.assertFalse(queue_exists('cf-test-queue-1'))
        self.assertFalse(topic_exists('%s-test-topic-1-1' % stack_name))
        retry(lambda: self.assertFalse(stream_exists('cf-test-stream-1')))

    def test_list_stack_events(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        response = cloudformation.describe_stack_events()
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

    def test_validate_template(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')

        template = template_deployer.template_to_json(load_file(TEST_VALID_TEMPLATE))
        resp = cloudformation.validate_template(TemplateBody=template)

        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('Parameters', resp)
        self.assertEqual(len(resp['Parameters']), 1)
        self.assertEqual(resp['Parameters'][0]['ParameterKey'], 'KeyExample')
        self.assertEqual(resp['Parameters'][0]['Description'], 'The EC2 Key Pair to allow SSH access to the instance')

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

        details = await_stack_completion(stack_name)

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
        template = load_file(TEST_TEMPLATE_4) % func_name
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
        s3.put_object(Bucket=TEST_ARTIFACTS_BUCKET, Key=TEST_ARTIFACTS_PATH, Body=load_file(TEST_TEMPLATE_5))

        # deploy template
        buckets_before = len(s3.list_buckets()['Buckets'])
        stack_name = 'stack-%s' % short_uid()
        param_value = short_uid()
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_TEMPLATE_6) % (TEST_ARTIFACTS_BUCKET, TEST_ARTIFACTS_PATH),
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

        template = json.loads(load_file(TEST_TEMPLATE_7))
        template['Resources']['LambdaExecutionRole']['Properties']['RoleName'] = lambda_role_name
        rs = cloudformation.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertIn('StackId', rs)
        self.assertIn(stack_name, rs['StackId'])

        await_stack_completion(stack_name)

        rs = lambda_client.list_functions()

        # There is 1 new lambda function
        self.assertEqual(lambdas_before + 1, len(rs['Functions']))

        # delete the stack
        cloudformation.delete_stack(StackName=stack_name)

        rs = lambda_client.list_functions()

        # Back to what we had before
        self.assertEqual(lambdas_before, len(rs['Functions']))

    def test_deploy_stack_change_set(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()
        bucket_name = 'bucket-%s' % short_uid()

        with self.assertRaises(ClientError) as ctx:
            cloudformation.describe_stacks(StackName=stack_name)
        self.assertEqual(ctx.exception.response['Error']['Code'], 'ValidationError')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=TEST_CHANGE_SET_BODY % bucket_name,
            Parameters=[{
                'ParameterKey': 'EnvironmentType',
                'ParameterValue': 'stage'
            }],
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
        self.assertEqual(rs['Status'], self.expected_change_set_status())

        rs = cloudformation.execute_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
        stack = rs['Stacks'][0]
        parameters = stack['Parameters']

        self.assertEqual(stack['StackName'], stack_name)
        self.assertEqual(parameters[0]['ParameterKey'], 'EnvironmentType')
        self.assertEqual(parameters[0]['ParameterValue'], 'stage')

        self.assertTrue(bucket_exists(bucket_name))

        # clean up
        self.cleanup(stack_name, change_set_name)

    def test_deploy_stack_with_iam_role(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()
        role_name = 'role-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        iam_client = aws_stack.connect_to_service('iam')
        roles_before = iam_client.list_roles()['Roles']

        with self.assertRaises(ClientError) as ctx:
            cloudformation.describe_stacks(StackName=stack_name)
        self.assertEqual(ctx.exception.response['Error']['Code'], 'ValidationError')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_1) % role_name
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        change_set_id = rs['Id']

        rs = cloudformation.describe_change_set(StackName=stack_name, ChangeSetName=change_set_id)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ChangeSetName'], change_set_name)
        self.assertEqual(rs['ChangeSetId'], change_set_id)
        self.assertEqual(rs['Status'], self.expected_change_set_status())

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
        stack = rs['Stacks'][0]
        self.assertEqual(stack['StackName'], stack_name)

        rs = iam_client.list_roles()
        self.assertEqual(len(rs['Roles']), len(roles_before) + 1)
        self.assertEqual(rs['Roles'][-1]['RoleName'], role_name)

        rs = iam_client.list_role_policies(RoleName=role_name)
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=rs['PolicyNames'][0])

        # clean up
        self.cleanup(stack_name, change_set_name)
        rs = iam_client.list_roles(PathPrefix=role_name)
        self.assertEqual(len(rs['Roles']), 0)

    def test_deploy_stack_with_sns_topic(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_2),
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

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        await_stack_completion(stack_name)

        rs = cloudformation.describe_stacks(StackName=stack_name)
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
        self.cleanup(stack_name, change_set_name)
        # assert topic resource removed
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
            TemplateBody=load_file(TEST_DEPLOY_BODY_3),
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

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        await_stack_completion(stack_name)
        rs = cloudformation.describe_stacks(StackName=stack_name)

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
        self.cleanup(stack_name, change_set_name)
        rs = ddb_client.list_tables()
        self.assertNotIn(ddb_table_name, rs['TableNames'])

    def test_deploy_stack_with_iam_nested_policy(self):
        stack_name = 'stack-%s' % short_uid()
        change_set_name = 'change-set-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        rs = cloudformation.create_change_set(
            StackName=stack_name,
            ChangeSetName=change_set_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_4)
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        change_set_id = rs['Id']

        rs = cloudformation.describe_change_set(StackName=stack_name, ChangeSetName=change_set_id)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ChangeSetId'], change_set_id)
        self.assertEqual(rs['Status'], self.expected_change_set_status())

        iam_client = aws_stack.connect_to_service('iam')
        rs = iam_client.list_roles()
        number_of_roles = len(rs['Roles'])

        rs = cloudformation.execute_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        await_stack_completion(stack_name)

        rs = iam_client.list_roles()
        # 1 role was created
        self.assertEqual(number_of_roles + 1, len(rs['Roles']))

        # clean up
        self.cleanup(stack_name, change_set_name)
        # assert role was removed
        rs = iam_client.list_roles()
        self.assertEqual(number_of_roles, len(rs['Roles']))

    def test_cfn_handle_s3_bucket_resources(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 's3-bucket-%s' % short_uid()

        TEST_TEMPLATE_8['Resources']['S3Bucket']['Properties']['BucketName'] = bucket_name

        self.assertFalse(bucket_exists(bucket_name))

        s3 = aws_stack.connect_to_service('s3')
        cfn = aws_stack.connect_to_service('cloudformation')

        deploy_cf_stack(stack_name=stack_name, template_body=json.dumps(TEST_TEMPLATE_8))

        self.assertTrue(bucket_exists(bucket_name))
        rs = s3.get_bucket_policy(Bucket=bucket_name)
        self.assertIn('Policy', rs)
        policy_doc = TEST_TEMPLATE_8['Resources']['S3BucketPolicy']['Properties']['PolicyDocument']
        self.assertEqual(json.loads(rs['Policy']), policy_doc)

        # clean up, assert resources deleted
        self.cleanup(stack_name,)

        self.assertFalse(bucket_exists(bucket_name))
        with self.assertRaises(ClientError) as ctx:
            s3.get_bucket_policy(Bucket=bucket_name)
        self.assertEqual(ctx.exception.response['Error']['Code'], 'NoSuchBucket')

        # recreate stack
        rs = cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(TEST_TEMPLATE_8))
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_log_group_resource(self):
        stack_name = 'stack-%s' % short_uid()
        log_group_prefix = '/aws/lambda/AWS_DUB_LAM_10000000'

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_9)

        logs_client = aws_stack.connect_to_service('logs')
        rs = logs_client.describe_log_groups(
            logGroupNamePrefix=log_group_prefix
        )

        self.assertEqual(len(rs['logGroups']), 1)
        self.assertEqual(rs['logGroups'][0]['logGroupName'],
                         '/aws/lambda/AWS_DUB_LAM_10000000_dev_MessageFooHandler_dev')

        # clean up and assert deletion
        self.cleanup(stack_name)
        rs = logs_client.describe_log_groups(logGroupNamePrefix=log_group_prefix)
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

        details = await_stack_completion(stack_name)
        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 3)

        rs = es_client.describe_elasticsearch_domain(DomainName=domain_name)
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

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_secretsmanager_secret(self):
        stack_name = 'stack-%s' % short_uid()
        secret_name = 'secret-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        params = [{'ParameterKey': 'SecretName', 'ParameterValue': secret_name}]
        cloudformation.create_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_11, Parameters=params)

        await_stack_completion(stack_name)

        secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
        self.assertEqual(secret_name, rs['Name'])
        self.assertNotIn('DeletedDate', rs)

        # clean up
        self.cleanup(stack_name)
        rs = secretsmanager_client.describe_secret(SecretId=secret_name)
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

        details = await_stack_completion(stack_name)

        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 1)

        kinesis_client = aws_stack.connect_to_service('kinesis')
        firehose_client = aws_stack.connect_to_service('firehose')

        rs = firehose_client.describe_delivery_stream(
            DeliveryStreamName=firehose_stream_name
        )
        self.assertEqual(outputs[0]['OutputValue'], rs['DeliveryStreamDescription']['DeliveryStreamARN'])
        self.assertEqual(firehose_stream_name, rs['DeliveryStreamDescription']['DeliveryStreamName'])

        rs = kinesis_client.describe_stream(StreamName=kinesis_stream_name)
        self.assertEqual(rs['StreamDescription']['StreamName'], kinesis_stream_name)

        # clean up
        self.cleanup(stack_name)
        time.sleep(1)
        rs = kinesis_client.list_streams()
        self.assertNotIn(kinesis_stream_name, rs['StreamNames'])
        rs = firehose_client.list_delivery_streams()
        self.assertNotIn(firehose_stream_name, rs['DeliveryStreamNames'])

    def test_cfn_handle_iam_role_resource(self):
        stack_name = 'stack-%s' % short_uid()
        role_name = 'role-%s' % short_uid()
        role_path_prefix = '/role-prefix-%s/' % short_uid()

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_13 % (role_name, role_path_prefix))

        iam = aws_stack.connect_to_service('iam')
        rs = iam.list_roles(PathPrefix=role_path_prefix)

        self.assertEqual(len(rs['Roles']), 1)
        role = rs['Roles'][0]
        self.assertEqual(role['RoleName'], role_name)

        # clean up
        self.cleanup(stack_name)
        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(len(rs['Roles']), 0)

    def test_cfn_handle_iam_role_resource_no_role_name(self):
        iam = aws_stack.connect_to_service('iam')

        stack_name = 'stack-%s' % short_uid()
        role_path_prefix = '/role-prefix-%s/' % short_uid()

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_14 % role_path_prefix)

        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(len(rs['Roles']), 1)

        # clean up
        self.cleanup(stack_name)
        rs = iam.list_roles(PathPrefix=role_path_prefix)
        self.assertEqual(len(rs['Roles']), 0)

    def test_describe_template(self):
        s3 = aws_stack.connect_to_service('s3')
        cloudformation = aws_stack.connect_to_service('cloudformation')

        bucket_name = 'b-%s' % short_uid()
        template_body = TEST_TEMPLATE_12 % 'test-firehose-role-name'
        s3.create_bucket(Bucket=bucket_name, ACL='public-read')
        s3.put_object(Bucket=bucket_name, Key='template.yml', Body=template_body)

        template_url = '%s/%s/template.yml' % (config.get_edge_url(), bucket_name)

        params = [{'ParameterKey': 'KinesisStreamName'}, {'ParameterKey': 'DeliveryStreamName'}]
        # get summary by template URL
        result = cloudformation.get_template_summary(TemplateURL=template_url)
        self.assertEqual(result.get('Parameters'), params)
        self.assertIn('AWS::S3::Bucket', result['ResourceTypes'])
        self.assertTrue(result.get('ResourceIdentifierSummaries'))
        # get summary by template body
        result = cloudformation.get_template_summary(TemplateBody=template_body)
        self.assertEqual(result.get('Parameters'), params)
        self.assertIn('AWS::Kinesis::Stream', result['ResourceTypes'])
        self.assertTrue(result.get('ResourceIdentifierSummaries'))

    def test_list_imports(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        result = cloudformation.list_imports(ExportName='_unknown_')
        self.assertEqual(result['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(result['Imports'], [])  # TODO: create test with actual import values!

    def test_cfn_conditional_deployment(self):
        s3 = aws_stack.connect_to_service('s3')

        bucket_id = short_uid()
        template = TEST_TEMPLATE_19.format(id=bucket_id)
        stack_name = 'stack-%s' % short_uid()
        deploy_cf_stack(stack_name=stack_name, template_body=template)

        buckets = s3.list_buckets()['Buckets']
        dev_bucket = 'cf-dev-%s' % bucket_id
        prd_bucket = 'cf-prd-%s' % bucket_id
        dev_bucket = [b for b in buckets if b['Name'] == dev_bucket]
        prd_bucket = [b for b in buckets if b['Name'] == prd_bucket]

        self.assertFalse(prd_bucket)
        self.assertTrue(dev_bucket)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_handle_sqs_resource(self):
        stack_name = 'stack-%s' % short_uid()
        fifo_queue = 'queue-%s.fifo' % short_uid()

        sqs = aws_stack.connect_to_service('sqs')

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_15 % fifo_queue)

        rs = sqs.get_queue_url(QueueName=fifo_queue)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        queue_url = rs['QueueUrl']

        rs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
        attributes = rs['Attributes']
        self.assertIn('ContentBasedDeduplication', attributes)
        self.assertIn('FifoQueue', attributes)
        self.assertEqual(attributes['ContentBasedDeduplication'], 'false')
        self.assertEqual(attributes['FifoQueue'], 'true')

        # clean up
        self.cleanup(stack_name)
        with self.assertRaises(ClientError) as ctx:
            sqs.get_queue_url(QueueName=fifo_queue)
        self.assertEqual(ctx.exception.response['Error']['Code'], 'AWS.SimpleQueueService.NonExistentQueue')

    def test_cfn_handle_events_rule(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 'target-%s' % short_uid()
        rule_prefix = 's3-rule-%s' % short_uid()
        rule_name = '%s-%s' % (rule_prefix, short_uid())

        events = aws_stack.connect_to_service('events')

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_16 % (bucket_name, rule_name))

        rs = events.list_rules(NamePrefix=rule_prefix)
        self.assertIn(rule_name, [rule['Name'] for rule in rs['Rules']])

        target_arn = aws_stack.s3_bucket_arn(bucket_name)
        rs = events.list_targets_by_rule(Rule=rule_name)
        self.assertIn(target_arn, [target['Arn'] for target in rs['Targets']])

        # clean up
        self.cleanup(stack_name)
        rs = events.list_rules(NamePrefix=rule_prefix)
        self.assertNotIn(rule_name, [rule['Name'] for rule in rs['Rules']])

    def test_cfn_handle_events_rule_without_name(self):
        events = aws_stack.connect_to_service('events')

        rs = events.list_rules()
        rule_names = [rule['Name'] for rule in rs['Rules']]

        stack_name = 'stack-%s' % short_uid()
        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_18 % aws_stack.role_arn('sfn_role'))

        rs = events.list_rules()
        new_rules = [rule for rule in rs['Rules'] if rule['Name'] not in rule_names]
        self.assertEqual(len(new_rules), 1)
        rule = new_rules[0]

        self.assertEqual(rule['ScheduleExpression'], 'cron(0/1 * * * ? *)')

        # clean up
        self.cleanup(stack_name)
        time.sleep(1)
        rs = events.list_rules()
        self.assertNotIn(rule['Name'], [r['Name'] for r in rs['Rules']])

    def test_cfn_handle_s3_notification_configuration(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 'target-%s' % short_uid()
        queue_name = 'queue-%s' % short_uid()
        queue_arn = aws_stack.sqs_queue_arn(queue_name)

        s3 = aws_stack.connect_to_service('s3')

        deploy_cf_stack(
            stack_name=stack_name, template_body=TEST_TEMPLATE_17 % (queue_name, bucket_name, queue_arn))

        rs = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        self.assertIn('QueueConfigurations', rs)
        self.assertEqual(len(rs['QueueConfigurations']), 1)
        self.assertEqual(rs['QueueConfigurations'][0]['QueueArn'], queue_arn)

        # clean up
        self.cleanup(stack_name)
        rs = s3.get_bucket_notification_configuration(Bucket=bucket_name)
        self.assertNotIn('QueueConfigurations', rs)

    def test_cfn_lambda_function_with_iam_role(self):
        stack_name = 'stack-%s' % short_uid()
        role_name = 'lambda-ex'

        iam = aws_stack.connect_to_service('iam')
        cloudformation = aws_stack.connect_to_service('cloudformation')

        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument='{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {'
                                     '"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]} '
        )
        self.assertEqual(role_name, response['Role']['RoleName'])

        response = iam.get_role(RoleName=role_name)
        self.assertEqual(role_name, response['Role']['RoleName'])

        role_arn = response['Role']['Arn']
        response = cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_20 % role_arn,
        )
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

        # clean up
        self.cleanup(stack_name)
        iam.delete_role(RoleName=role_name)

    def test_cfn_handle_serverless_api_resource(self):
        stack_name = 'stack-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')

        deploy_cf_stack(stack_name=stack_name, template_body=TEST_TEMPLATE_22)

        res = cloudformation.list_stack_resources(StackName=stack_name)['StackResourceSummaries']
        rest_api_ids = [r['PhysicalResourceId'] for r in res if r['ResourceType'] == 'AWS::ApiGateway::RestApi']
        lambda_func_names = [r['PhysicalResourceId'] for r in res if r['ResourceType'] == 'AWS::Lambda::Function']

        self.assertEqual(len(rest_api_ids), 1)
        self.assertEqual(len(lambda_func_names), 1)

        apigw_client = aws_stack.connect_to_service('apigateway')
        rs = apigw_client.get_resources(
            restApiId=rest_api_ids[0]
        )
        self.assertEqual(len(rs['items']), 1)
        resource = rs['items'][0]

        uri = resource['resourceMethods']['GET']['methodIntegration']['uri']
        lambda_arn = aws_stack.lambda_function_arn(lambda_func_names[0])
        self.assertIn(lambda_arn, uri)

        # clean up
        self.cleanup(stack_name)

    def test_delete_stack(self):
        domain_name = 'es-%s' % short_uid()
        stack_name1 = 's1-%s' % short_uid()
        stack_name2 = 's2-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        cloudformation.create_stack(
            StackName=stack_name1, TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )

        cloudformation.create_stack(
            StackName=stack_name2, TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )

        # clean up
        cloudformation.delete_stack(StackName=stack_name1)
        cloudformation.delete_stack(StackName=stack_name2)

    def test_cfn_with_on_demand_dynamodb_resource(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')

        stack_name = 'test-%s' % short_uid()
        response = cloudformation.create_stack(StackName=stack_name, TemplateBody=load_file(TEST_TEMPLATE_21))

        self.assertIn('StackId', response)
        self.assertEqual(200, response['ResponseMetadata']['HTTPStatusCode'])

        # clean up
        self.cleanup(stack_name)

    def test_update_lambda_function(self):
        bucket_name = 'bucket-{}'.format(short_uid())
        key_name = 'lambda-package'
        role_name = 'role-{}'.format(short_uid())
        function_name = 'func-{}'.format(short_uid())

        package_path = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.js')

        stack_name = 'stack-{}'.format(short_uid())
        cloudformation = aws_stack.connect_to_service('cloudformation')

        template = json.loads(load_file(TEST_UPDATE_LAMBDA_FUNCTION_TEMPLATE))
        template['Resources']['PullMarketsRole']['Properties']['RoleName'] = role_name

        props = template['Resources']['SomeNameFunction']['Properties']
        props['Code']['S3Bucket'] = bucket_name
        props['Code']['S3Key'] = key_name
        props['FunctionName'] = function_name

        s3 = aws_stack.connect_to_service('s3')
        s3.create_bucket(Bucket=bucket_name, ACL='public-read')
        s3.put_object(Bucket=bucket_name, Key=key_name, Body=create_zip_file(package_path, get_content=True))
        time.sleep(1)

        rs = cloudformation.create_stack(StackName=stack_name, TemplateBody=json.dumps(template),)
        self.assertEqual(200, rs['ResponseMetadata']['HTTPStatusCode'])

        props.update({
            'Environment': {'Variables': {'AWS_NODEJS_CONNECTION_REUSE_ENABLED': 1}}
        })

        rs = cloudformation.update_stack(StackName=stack_name, TemplateBody=json.dumps(template),)
        self.assertEqual(200, rs['ResponseMetadata']['HTTPStatusCode'])
        lambda_client = aws_stack.connect_to_service('lambda')

        rs = lambda_client.get_function(FunctionName=function_name)
        self.assertEqual(rs['Configuration']['FunctionName'], function_name)
        self.assertIn('AWS_NODEJS_CONNECTION_REUSE_ENABLED', rs['Configuration']['Environment']['Variables'])

        # clean up
        self.cleanup(stack_name)

    def test_cfn_deploy_apigateway_integration(self):
        stack_name = 'stack-%s' % short_uid()
        bucket_name = 'hofund-local-deployment'
        key_name = 'serverless/hofund/local/1599143878432/authorizer.zip'
        package_path = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.js')

        template = template_deployer.template_to_json(load_file(APIGW_INTEGRATION_TEMPLATE))

        s3 = aws_stack.connect_to_service('s3')
        s3.create_bucket(Bucket=bucket_name, ACL='public-read')
        s3.put_object(Bucket=bucket_name, Key=key_name, Body=create_zip_file(package_path, get_content=True))

        cloudformation = aws_stack.connect_to_service('cloudformation')
        apigw_client = aws_stack.connect_to_service('apigateway')

        rs = cloudformation.create_stack(StackName=stack_name, TemplateBody=template)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        stack_resources = cloudformation.list_stack_resources(StackName=stack_name)['StackResourceSummaries']
        rest_apis = [res for res in stack_resources if res['ResourceType'] == 'AWS::ApiGateway::RestApi']

        rs = apigw_client.get_rest_api(restApiId=rest_apis[0]['PhysicalResourceId'])
        self.assertEqual(rs['name'], 'ApiGatewayRestApi')

        # clean up
        self.cleanup(stack_name)

    def test_globalindex_read_write_provisioned_throughput_dynamodb_table(self):
        cf_client = aws_stack.connect_to_service('cloudformation')
        ddb_client = aws_stack.connect_to_service('dynamodb')
        stack_name = 'test_dynamodb'

        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_DEPLOY_BODY_3),
            Parameters=[{
                'ParameterKey': 'tableName',
                'ParameterValue': 'dynamodb'
            }, {
                'ParameterKey': 'env',
                'ParameterValue': 'test'
            }]
        )
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        response = ddb_client.describe_table(TableName='dynamodb-test')

        if response['Table']['ProvisionedThroughput']:
            throughput = response['Table']['ProvisionedThroughput']
            self.assertTrue(isinstance(throughput['ReadCapacityUnits'], int))
            self.assertTrue(isinstance(throughput['WriteCapacityUnits'], int))

        for global_index in response['Table']['GlobalSecondaryIndexes']:
            index_provisioned = global_index['ProvisionedThroughput']
            test_read_capacity = index_provisioned['ReadCapacityUnits']
            test_write_capacity = index_provisioned['WriteCapacityUnits']
            self.assertTrue(isinstance(test_read_capacity, int))
            self.assertTrue(isinstance(test_write_capacity, int))

        # clean up
        self.cleanup(stack_name)

    def test_delete_stack_across_regions(self):
        domain_name = 'es-%s' % short_uid()
        stack_name = 'stack-%s' % short_uid()

        s3 = aws_stack.connect_to_service('s3', region_name='eu-central-1')
        cloudformation = aws_stack.connect_to_service('cloudformation', region_name='eu-central-1')

        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_3,
            Parameters=[{'ParameterKey': 'DomainName', 'ParameterValue': domain_name}]
        )
        await_stack_completion(stack_name)
        bucket_name = TEST_TEMPLATE_3.split('BucketName:')[1].split('\n')[0].strip()
        response = s3.head_bucket(Bucket=bucket_name)
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        self.cleanup(stack_name)
        with self.assertRaises(Exception):
            s3.head_bucket(Bucket=bucket_name)

    def test_update_stack_with_same_template(self):
        stack_name = 'stack-%s' % short_uid()
        template_data = load_file(SQS_TEMPLATE)
        cloudformation = aws_stack.connect_to_service('cloudformation')

        params = {
            'StackName': stack_name,
            'TemplateBody': template_data
        }
        cloudformation.create_stack(**params)

        with self.assertRaises(Exception) as ctx:
            cloudformation.update_stack(**params)
            waiter = cloudformation.get_waiter('stack_update_complete')
            waiter.wait(StackName=stack_name)

        error_message = str(ctx.exception)
        self.assertIn('UpdateStack', error_message)
        self.assertIn('No updates are to be performed.', error_message)

        # clean up
        self.cleanup(stack_name)

    def test_cdk_template(self):
        stack_name = 'stack-%s' % short_uid()
        bucket = 'bucket-%s' % short_uid()
        key = 'key-%s' % short_uid()
        path = os.path.join(THIS_FOLDER, 'templates', 'asset')

        s3_client = aws_stack.connect_to_service('s3')
        s3_client.create_bucket(Bucket=bucket)
        s3_client.put_object(Bucket=bucket, Key=key, Body=create_zip_file(path, get_content=True))

        template = load_file(os.path.join(THIS_FOLDER, 'templates', 'cdktemplate.json'))

        cloudformation = aws_stack.connect_to_service('cloudformation')
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{
                'ParameterKey': 'AssetParameters1S3BucketEE4ED9A8',
                'ParameterValue': bucket
            }, {
                'ParameterKey': 'AssetParameters1S3VersionKeyE160C88A',
                'ParameterValue': key
            }]
        )
        await_stack_completion(stack_name)

        lambda_client = aws_stack.connect_to_service('lambda')

        resp = lambda_client.list_functions()
        functions = [func for func in resp['Functions'] if stack_name in func['FunctionName']]

        self.assertEqual(len(functions), 2)
        self.assertEqual(len([func for func in functions if func['Handler'] == 'index.createUserHandler']), 1)
        self.assertEqual(len([func for func in functions if func['Handler'] == 'index.authenticateUserHandler']), 1)

        # clean up
        self.cleanup(stack_name)

    def test_cfn_template_with_short_form_fn_sub(self):
        stack_name = 'stack-%s' % short_uid()
        environment = 'env-%s' % short_uid()

        cloudformation = aws_stack.connect_to_service('cloudformation')
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=load_file(TEST_TEMPLATE_23),
            Parameters=[{
                'ParameterKey': 'Environment',
                'ParameterValue': environment
            }, {
                'ParameterKey': 'ApiKey',
                'ParameterValue': '12345'
            }]
        )
        iam_client = aws_stack.connect_to_service('iam')
        rs = iam_client.list_roles()

        # 2 roles created successfully
        roles = [role for role in rs['Roles']
                 if role['RoleName'] in ['cf-{}-Role'.format(stack_name),
                                         'cf-{}-StateMachineExecutionRole'.format(stack_name)]]

        self.assertEqual(len(roles), 2)

        sfn_client = aws_stack.connect_to_service('stepfunctions')
        state_machines_after = sfn_client.list_state_machines()['stateMachines']

        state_machines = [sm for sm in state_machines_after if '{}-StateMachine-'.format(stack_name) in sm['name']]

        self.assertEqual(len(state_machines), 1)
        rs = sfn_client.describe_state_machine(stateMachineArn=state_machines[0]['stateMachineArn'])

        definition = json.loads(rs['definition'].replace('\n', ''))
        payload = definition['States']['time-series-update']['Parameters']['Payload']
        self.assertEqual(payload, {'key': '12345'})

        # clean up
        self.cleanup(stack_name)

    def test_sub_in_lambda_function_name(self):
        stack_name = 'stack-%s' % short_uid()
        environment = 'env-%s' % short_uid()
        bucket = 'bucket-%s' % short_uid()
        key = 'key-%s' % short_uid()

        package_path = os.path.join(THIS_FOLDER, 'lambdas', 'lambda_echo.js')

        s3 = aws_stack.connect_to_service('s3')
        s3.create_bucket(Bucket=bucket, ACL='public-read')
        s3.put_object(Bucket=bucket, Key=key, Body=create_zip_file(package_path, get_content=True))
        time.sleep(1)

        template = load_file(TEST_TEMPLATE_24) % (bucket, key, bucket, key)

        cloudformation = aws_stack.connect_to_service('cloudformation')
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[{
                'ParameterKey': 'Environment',
                'ParameterValue': environment
            }]
        )
        await_stack_completion(stack_name)

        lambda_client = aws_stack.connect_to_service('lambda')
        functions = lambda_client.list_functions()['Functions']

        # assert Lambda functions created with expected name and ARN
        func_prefix = 'test-{}-connectionHandler'.format(environment)
        functions = [func for func in functions if func['FunctionName'].startswith(func_prefix)]
        self.assertEqual(len(functions), 2)
        func1 = [f for f in functions if f['FunctionName'].endswith('connectionHandler1')][0]
        func2 = [f for f in functions if f['FunctionName'].endswith('connectionHandler2')][0]
        self.assertTrue(func1['FunctionArn'].endswith(func1['FunctionName']))
        self.assertTrue(func2['FunctionArn'].endswith(func2['FunctionName']))

        # assert buckets which reference Lambda names have been created
        s3_client = aws_stack.connect_to_service('s3')
        buckets = s3_client.list_buckets()['Buckets']
        buckets = [b for b in buckets if b['Name'].startswith(func_prefix.lower())]
        # assert buckets are created correctly
        self.assertEqual(len(functions), 2)
        tags1 = s3_client.get_bucket_tagging(Bucket=buckets[0]['Name'])
        tags2 = s3_client.get_bucket_tagging(Bucket=buckets[1]['Name'])
        # assert correct tags - they reference the function names and should equal the bucket names (lower case)
        self.assertEqual(tags1['TagSet'][0]['Value'].lower(), buckets[0]['Name'])
        self.assertEqual(tags2['TagSet'][0]['Value'].lower(), buckets[1]['Name'])

        # clean up
        self.cleanup(stack_name)

    def test_lambda_dependency(self):
        lambda_client = aws_stack.connect_to_service('lambda')
        stack_name = 'stack-%s' % short_uid()

        template = load_file(TEST_TEMPLATE_25)

        details = deploy_cf_stack(stack_name, template_body=template)

        # assert Lambda function created properly
        resp = lambda_client.list_functions()
        func_name = 'test-forward-sns'
        functions = [func for func in resp['Functions'] if func['FunctionName'] == func_name]
        self.assertEqual(len(functions), 1)

        # assert that stack outputs are returned properly
        outputs = details.get('Outputs', [])
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0]['ExportName'], 'FuncArnExportName123')

        # clean up
        self.cleanup(stack_name)

    def test_functions_in_output_export_name(self):
        stack_name = 'stack-%s' % short_uid()
        environment = 'env-%s' % short_uid()
        template = load_file(os.path.join(THIS_FOLDER, 'templates', 'template26.yaml'))

        cfn = aws_stack.connect_to_service('cloudformation')
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Parameters=[
                {
                    'ParameterKey': 'Environment',
                    'ParameterValue': environment
                }
            ]
        )
        await_stack_completion(stack_name)

        resp = cfn.describe_stacks(StackName=stack_name)
        stack_outputs = [stack['Outputs'] for stack in resp['Stacks'] if stack['StackName'] == stack_name]
        self.assertEqual(len(stack_outputs), 1)

        outputs = {o['OutputKey']: {'value': o['OutputValue'], 'export': o['ExportName']} for o in stack_outputs[0]}

        self.assertIn('VpcId', outputs)
        self.assertEqual(outputs['VpcId'].get('export'), '{}-vpc-id'.format(environment))

        topic_arn = aws_stack.sns_topic_arn('{}-slack-sns-topic'.format(environment))
        self.assertIn('TopicArn', outputs)
        self.assertEqual(outputs['TopicArn'].get('export'), topic_arn)

        # clean up
        self.cleanup(stack_name)

    def cleanup(self, stack_name, change_set_name=None):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        if change_set_name:
            cloudformation.delete_change_set(StackName=stack_name, ChangeSetName=change_set_name)
        resp = cloudformation.delete_stack(StackName=stack_name)
        self.assertEqual(resp['ResponseMetadata']['HTTPStatusCode'], 200)

    def expected_change_set_status(self):
        return 'CREATE_COMPLETE'
