import os
import unittest

from localstack.services.awslambda import lambda_api
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.constants import LAMBDA_TEST_ROLE

os.environ['AWS_ACCESS_KEY_ID'] = 'test'
os.environ['AWS_SECRET_ACCESS_KEY'] = 'test'


class TestLambdaEventInvokeConfig(unittest.TestCase):
    CODE_SIZE = 50
    CODE_SHA_256 = '/u60ZpAA9bzZPVwb8d4390i5oqP1YAObUwV03CZvsWA='
    MEMORY_SIZE = 128
    ROLE = LAMBDA_TEST_ROLE
    LAST_MODIFIED = '2019-05-25T17:00:48.260+0000'
    REVISION_ID = 'e54dbcf8-e3ef-44ab-9af7-8dbef510608a'
    HANDLER = 'index.handler'
    RUNTIME = 'node.js4.3'
    TIMEOUT = 60
    FUNCTION_NAME = 'test1'
    RETRY_ATTEMPTS = 5
    EVENT_AGE = 360
    DL_QUEUE = 'arn:aws:sqs:us-east-1:000000000000:dlQueue'
    LAMBDA_OBJ = LambdaFunction(lambda_api.func_arn('test1'))

    def _create_function(self, function_name, tags={}):
        self.LAMBDA_OBJ.versions = {
            '$LATEST': {'CodeSize': self.CODE_SIZE, 'CodeSha256': self.CODE_SHA_256, 'RevisionId': self.REVISION_ID}
        }
        self.LAMBDA_OBJ.handler = self.HANDLER
        self.LAMBDA_OBJ.runtime = self.RUNTIME
        self.LAMBDA_OBJ.timeout = self.TIMEOUT
        self.LAMBDA_OBJ.tags = tags
        self.LAMBDA_OBJ.envvars = {}
        self.LAMBDA_OBJ.last_modified = self.LAST_MODIFIED
        self.LAMBDA_OBJ.role = self.ROLE
        self.LAMBDA_OBJ.memory_size = self.MEMORY_SIZE

    def test_put_function_event_invoke_config(self):
        # creating a lambda function
        self._create_function(self.FUNCTION_NAME)

        # calling put_function_event_invoke_config
        payload = {
            'DestinationConfig': {
                'OnFailure': {
                    'Destination': self.DL_QUEUE
                }
            },
            'MaximumEventAgeInSeconds': self.EVENT_AGE,
            'MaximumRetryAttempts': self.RETRY_ATTEMPTS
        }
        response = self.LAMBDA_OBJ.put_function_event_invoke_config(
            payload
        )
        # checking if response is not None
        self.assertIsNotNone(response)

        # calling get_function_event_invoke_config
        response = self.LAMBDA_OBJ.get_function_event_invoke_config()
        # verifying set values
        self.assertEqual(response['FunctionArn'], self.LAMBDA_OBJ.id)
        self.assertEqual(response['MaximumRetryAttempts'], self.RETRY_ATTEMPTS)
        self.assertEqual(response['MaximumEventAgeInSeconds'], self.EVENT_AGE)
        self.assertEqual(response['DestinationConfig']['OnFailure']['Destination'], self.DL_QUEUE)
