import unittest
import json
from flask import Flask
from localstack.services.awslambda import lambda_api
from localstack.utils.aws.aws_models import LambdaFunction


class TestLambdaAPI(unittest.TestCase):
    CODE_SIZE = 50
    HANDLER = 'index.handler'
    RUNTIME = 'node.js4.3'
    TIMEOUT = 60  # Default value, hardcoded
    FUNCTION_NAME = 'test1'
    RESOURCENOTFOUND_EXCEPTION = 'ResourceNotFoundException'
    RESOURCENOTFOUND_MESSAGE = 'Function not found: %s'
    TEST_UUID = "Test"

    def setUp(self):
        lambda_api.cleanup()
        self.maxDiff = None
        self.app = Flask(__name__)

    def test_delete_event_source_mapping(self):
        with self.app.test_request_context():
            lambda_api.event_source_mappings.append({'UUID': self.TEST_UUID})
            result = lambda_api.delete_event_source_mapping(self.TEST_UUID)
            self.assertEqual(json.loads(result.get_data()).get('UUID'), self.TEST_UUID)
            self.assertEqual(0, len(lambda_api.event_source_mappings))

    def test_publish_function_version(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)

            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            result2 = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())

            expected_result = dict()
            expected_result[u'CodeSize'] = self.CODE_SIZE
            expected_result[u'FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME))
            expected_result[u'FunctionName'] = str(self.FUNCTION_NAME)
            expected_result[u'Handler'] = str(self.HANDLER)
            expected_result[u'Runtime'] = str(self.RUNTIME)
            expected_result[u'Timeout'] = self.TIMEOUT
            expected_result[u'Version'] = 1
            expected_result2 = dict(expected_result)
            expected_result2[u'Version'] = 2
            self.assertDictEqual(expected_result, result)
            self.assertDictEqual(expected_result2, result2)

    def test_publish_non_existant_function_version_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.publish_version(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def test_list_function_versions(self):
        with self.app.test_request_context():
            self._create_function(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)
            lambda_api.publish_version(self.FUNCTION_NAME)

            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())

            latest_version = dict()
            latest_version[u'CodeSize'] = self.CODE_SIZE
            latest_version[u'FunctionArn'] = str(lambda_api.func_arn(self.FUNCTION_NAME))
            latest_version[u'FunctionName'] = str(self.FUNCTION_NAME)
            latest_version[u'Handler'] = str(self.HANDLER)
            latest_version[u'Runtime'] = str(self.RUNTIME)
            latest_version[u'Timeout'] = self.TIMEOUT
            latest_version[u'Version'] = u'$LATEST'
            version1 = dict(latest_version)
            version1[u'Version'] = 1
            version2 = dict(latest_version)
            version2[u'Version'] = 2
            expected_result = {u'Versions': sorted([latest_version, version1, version2],
                                                   key=lambda k: str(k.get('Version')))}
            self.assertDictEqual(expected_result, result)

    def test_list_non_existant_function_versions_returns_error(self):
        with self.app.test_request_context():
            result = json.loads(lambda_api.list_versions(self.FUNCTION_NAME).get_data())
            self.assertEqual(self.RESOURCENOTFOUND_EXCEPTION, result['__type'])
            self.assertEqual(self.RESOURCENOTFOUND_MESSAGE % lambda_api.func_arn(self.FUNCTION_NAME),
                             result['message'])

    def _create_function(self, function_name):
        arn = lambda_api.func_arn(function_name)
        lambda_api.arn_to_lambda[arn] = LambdaFunction(arn)
        lambda_api.arn_to_lambda[arn].versions = {'$LATEST': {'CodeSize': self.CODE_SIZE}}
        lambda_api.arn_to_lambda[arn].handler = self.HANDLER
        lambda_api.arn_to_lambda[arn].runtime = self.RUNTIME
        lambda_api.arn_to_lambda[arn].envvars = {}
