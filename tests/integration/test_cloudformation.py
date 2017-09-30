import os
import unittest
from localstack.utils.aws import aws_stack
from localstack.utils.common import load_file, retry
from localstack.utils.cloudformation import template_deployer
from botocore.exceptions import ClientError
from botocore.parsers import ResponseParserError

THIS_FOLDER = os.path.dirname(os.path.realpath(__file__))
TEST_TEMPLATE_1 = os.path.join(THIS_FOLDER, 'templates', 'template1.yaml')

TEST_STACK_NAME = 'test-cf-stack-1'


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


def stream_exists(name):
    kinesis_client = aws_stack.connect_to_service('kinesis')
    streams = kinesis_client.list_streams()
    return name in streams['StreamNames']


def get_stack_details(stack_name):
    cloudformation = aws_stack.connect_to_service('cloudformation')
    stacks = cloudformation.describe_stacks(StackName=TEST_STACK_NAME)
    for stack in stacks['Stacks']:
        if stack['StackName'] == stack_name:
            return stack


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
                assert err.response['ResponseMetadata']['HTTPStatusCode'] == 400
                assert err.response['Error']['Message'] == 'Template Validation Error'
