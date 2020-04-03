import os
import logging
import json
import unittest

from botocore.exceptions import ClientError

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.kinesis import kinesis_connector


class TestIAMIntegrations(unittest.TestCase):
    def setUp(self):
        self.iam_client = aws_stack.connect_to_service('iam')

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
                wait_until_started=True
            )

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

        self.iam_client.create_user(UserName=test_user_name)
        response = self.iam_client.create_policy(
            PolicyName='test-policy',
            PolicyDocument=json.dumps(test_policy_document)
        )
        test_policy_arn = response['Policy']['Arn']
        self.assertIn(TEST_AWS_ACCOUNT_ID, test_policy_arn)

        self.iam_client.attach_user_policy(UserName=test_user_name, PolicyArn=test_policy_arn)
        attached_user_policies = self.iam_client.list_attached_user_policies(UserName=test_user_name)

        self.assertEqual(len(attached_user_policies['AttachedPolicies']), 1)
        self.assertEqual(attached_user_policies['AttachedPolicies'][0]['PolicyArn'], test_policy_arn)

        # clean up
        self.iam_client.detach_user_policy(
            UserName=test_user_name,
            PolicyArn=test_policy_arn
        )
        self.iam_client.delete_policy(
            PolicyArn=test_policy_arn
        )
        self.iam_client.delete_user(
            UserName=test_user_name
        )

    def test_recreate_iam_role(self):
        role_name = 'role-{}'.format(short_uid())

        assume_policy_document = {
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Action': 'sts:AssumeRole',
                    'Principal': {'Service': 'lambda.amazonaws.com'}
                }
            ]
        }

        rs = self.iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_policy_document)
        )
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        try:
            # Create role with same name
            self.iam_client.create_role(
                RoleName=role_name,
                AssumeRolePolicyDocument=json.dumps(assume_policy_document)
            )
            self.fail('This call should not be successful as the role already exists')

        except ClientError as e:
            self.assertEqual(e.response['Error']['Code'], 'EntityAlreadyExists')

        # clean up
        self.iam_client.delete_role(
            RoleName=role_name
        )
