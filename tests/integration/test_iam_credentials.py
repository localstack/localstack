import os
import logging
import json
import unittest

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.kinesis import kinesis_connector


class TestIAMIntegrations(unittest.TestCase):

    def test_run_kcl_with_iam_assume_role(self):
        env_vars = {}
        if os.environ.get('AWS_ASSUME_ROLE_ARN'):
            env_vars['AWS_ASSUME_ROLE_ARN'] = os.environ.get('AWS_ASSUME_ROLE_ARN')
            env_vars['AWS_ASSUME_ROLE_SESSION_NAME'] = os.environ.get('AWS_ASSUME_ROLE_SESSION_NAME')
            env_vars['ENV'] = os.environ.get('ENV') or 'main'

            def process_records(records):
                print(records)

            # start Kinesis client
            stream_name = 'test-foobar'
            kinesis_connector.listen_to_kinesis(
                stream_name=stream_name,
                listener_func=process_records,
                env_vars=env_vars,
                kcl_log_level=logging.INFO,
                wait_until_started=True)

    def test_attach_iam_role_to_new_iam_user(self):
        test_policy_document = {
            'Version': '2012-10-17',
            'Statement': {
                'Effect': 'Allow',
                'Action': 's3:ListBucket',
                'Resource': 'arn:aws:s3:::example_bucket'
            }
        }
        test_user_name = 'test-user'

        iam_client = aws_stack.connect_to_service('iam')

        iam_client.create_user(UserName=test_user_name)
        response = iam_client.create_policy(PolicyName='test-policy',
                                            PolicyDocument=json.dumps(test_policy_document))
        test_policy_arn = response['Policy']['Arn']
        self.assertIn(TEST_AWS_ACCOUNT_ID, test_policy_arn)
        iam_client.attach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        attached_user_policies = iam_client.list_attached_user_policies(UserName=test_user_name)
        self.assertEqual(len(attached_user_policies['AttachedPolicies']), 1)
        self.assertEqual(attached_user_policies['AttachedPolicies'][0]['PolicyArn'], test_policy_arn)
