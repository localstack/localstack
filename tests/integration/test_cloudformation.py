import os
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file, retry
from localstack.utils.cloudformation import template_deployer
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_TEMPLATE_1 = os.path.join(THIS_FOLDER, 'templates', 'template1.yaml')
TEST_TEMPLATE_2 = os.path.join(THIS_FOLDER, 'templates', 'template2.yaml')

TEST_STACK_NAME = 'test-cf-stack-1'
TEST_STACK_NAME_2 = 'test-cf-stack-2'


def bucket_exists(name):
    s3_client = aws_stack.connect_to_service('s3')
    buckets = s3_client.list_buckets()
    for bucket in buckets['Buckets']:
        if bucket['Name'] == name:
            return True


def queue_exists(name):
    sqs_client = aws_stack.connect_to_service('sqs')
    queues = sqs_client.list_queues()
    for queue_url in queues['QueueUrls']:
        if queue_url.endswith('/%s' % name):
            return True


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

    def test_apply_template(self):
        cloudformation = aws_stack.connect_to_resource('cloudformation')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_1))

        # deploy template
        cloudformation.create_stack(StackName=TEST_STACK_NAME, TemplateBody=template)

        # wait for deployment to finish
        def check_stack():
            stack = get_stack_details(TEST_STACK_NAME)
            assert stack['StackStatus'] == 'CREATE_COMPLETE'

        retry(check_stack, retries=3, sleep=2)

        # assert that bucket has been created
        assert bucket_exists('cf-test-bucket-1')
        # assert that queue has been created
        assert queue_exists('cf-test-queue-1')
        # assert that stream has been created
        assert stream_exists('cf-test-stream-1')
        # assert that queue has been created
        resource = describe_stack_resource(TEST_STACK_NAME, 'SQSQueueNoNameProperty')
        assert queue_exists(resource['PhysicalResourceId'])

    def test_validate_template(self):
        cloudformation = aws_stack.connect_to_service('cloudformation')
        template = template_deployer.template_to_json(load_file(TEST_TEMPLATE_1))
        response = cloudformation.validate_template(TemplateBody=template)
        assert response['ResponseMetadata']['HTTPStatusCode'] == 200

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
        cloudformation.create_stack(StackName=TEST_STACK_NAME_2, TemplateBody=template)

        def check_stack():
            stack = get_stack_details(TEST_STACK_NAME_2)
            assert stack['StackStatus'] == 'CREATE_COMPLETE'

        retry(check_stack, retries=3, sleep=2)

        list_stack_summaries = list_stack_resources(TEST_STACK_NAME_2)
        queue_urls = get_queue_urls()
        topic_arns = get_topic_arns()

        stack_queues = [r for r in list_stack_summaries if r['ResourceType'] == 'AWS::SQS::Queue']
        for resource in stack_queues:
            url = aws_stack.get_sqs_queue_url(resource['PhysicalResourceId'])
            self.assertIn(url, queue_urls)

        stack_topics = [r for r in list_stack_summaries if r['ResourceType'] == 'AWS::SNS::Topic']
        for resource in stack_topics:
            self.assertIn(resource['PhysicalResourceId'], topic_arns)
