import os
import json
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
  MyFunc:
    Type: AWS::Serverless::Function
    Properties:
      FunctionName: %s
      Handler: index.handler
      Runtime:
        Ref: LambdaRuntime
      InlineCode: |
        def handler(event, context):
            return {'hello': 'world'}
"""
TEST_TEMPLATE_5 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  S3Setup:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: test-%s
""" % short_uid()
TEST_ARTIFACTS_BUCKET = 'cf-artifacts'
TEST_ARTIFACTS_PATH = 'stack.yaml'
TEST_TEMPLATE_6 = """
AWSTemplateFormatVersion: 2010-09-09
Resources:
  NestedStack:
    Type: AWS::CloudFormation::Stack
    Properties:
      TemplateURL: http://localhost:4572/%s/%s
""" % (TEST_ARTIFACTS_BUCKET, TEST_ARTIFACTS_PATH)


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
            return True


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


class CloudFormationTest(unittest.TestCase):

    def test_create_delete_stack(self):
        cloudformation = aws_stack.connect_to_resource('cloudformation')
        cf_client = aws_stack.connect_to_service('cloudformation')
        s3 = aws_stack.connect_to_service('s3')
        sns = aws_stack.connect_to_service('sns')
        apigateway = aws_stack.connect_to_service('apigateway')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_1))

        # deploy template
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=template)

        # wait for deployment to finish
        def check_stack():
            stack = get_stack_details(stack_name)
            self.assertEqual(stack['StackStatus'], 'CREATE_COMPLETE')

        retry(check_stack, retries=3, sleep=2)

        # assert that resources have been created
        assert bucket_exists('cf-test-bucket-1')
        assert queue_exists('cf-test-queue-1')
        topic_arn = topic_exists('%s-test-topic-1-1' % stack_name)
        assert topic_arn
        assert stream_exists('cf-test-stream-1')
        resource = describe_stack_resource(stack_name, 'SQSQueueNoNameProperty')
        assert queue_exists(resource['PhysicalResourceId'])

        # assert that tags have been created
        tags = s3.get_bucket_tagging(Bucket='cf-test-bucket-1')['TagSet']
        self.assertEqual(tags, [{'Key': 'foobar', 'Value': aws_stack.get_sqs_queue_url('cf-test-queue-1')}])
        tags = sns.list_tags_for_resource(ResourceArn=topic_arn)['Tags']
        self.assertEqual(tags, [
            {'Key': 'foo', 'Value': 'cf-test-bucket-1'},
            {'Key': 'bar', 'Value': aws_stack.s3_bucket_arn('cf-test-bucket-1')}
        ])

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

        def check_stack():
            stack = get_stack_details(stack_name)
            self.assertEqual(stack['StackStatus'], 'CREATE_COMPLETE')

        retry(check_stack, retries=3, sleep=2)

        stack_summaries = list_stack_resources(stack_name)
        queue_urls = get_queue_urls()
        topic_arns = get_topic_arns()

        stack_queues = [r for r in stack_summaries if r['ResourceType'] == 'AWS::SQS::Queue']
        for resource in stack_queues:
            self.assertIn(resource['PhysicalResourceId'], queue_urls)

        stack_topics = [r for r in stack_summaries if r['ResourceType'] == 'AWS::SNS::Topic']
        for resource in stack_topics:
            self.assertIn(resource['PhysicalResourceId'], topic_arns)

    def test_create_change_set(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')

        # deploy template
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_3)

        # create change set with the same template (no changes)
        response = cloudformation.create_change_set(StackName=stack_name,
            TemplateBody=TEST_TEMPLATE_3, ChangeSetName='nochanges')
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

    def test_nested_stack(self):
        s3 = aws_stack.connect_to_service('s3')
        cloudformation = aws_stack.connect_to_service('cloudformation')

        # upload template to S3
        s3.create_bucket(Bucket=TEST_ARTIFACTS_BUCKET, ACL='public-read')
        s3.put_object(Bucket=TEST_ARTIFACTS_BUCKET, Key=TEST_ARTIFACTS_PATH, Body=TEST_TEMPLATE_5)

        # deploy template
        buckets_before = len(s3.list_buckets()['Buckets'])
        stack_name = 'stack-%s' % short_uid()
        cloudformation.create_stack(StackName=stack_name, TemplateBody=TEST_TEMPLATE_6)

        # assert that nested resources have been created
        buckets_after = len(s3.list_buckets()['Buckets'])
        self.assertEqual(buckets_after, buckets_before + 1)
