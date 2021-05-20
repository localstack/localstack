import unittest
import json
from datetime import datetime
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid

RESOURCE_POLICY = {
    'Version': '2012-10-17',
    'Statement': [{
        'Effect': 'Allow',
        'Principal': {
            'AWS': 'arn:aws:iam::%s:root' % TEST_AWS_ACCOUNT_ID
        },
        'Action': 'secretsmanager:GetSecretValue',
        'Resource': '*'
    }]
}


class SecretsManagerTest(unittest.TestCase):
    def setUp(self):
        self.secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

    def test_create_and_update_secret(self):
        secret_name = 's-%s' % short_uid()
        rs = self.secretsmanager_client.create_secret(
            Name=secret_name, SecretString='my_secret', Description='testing creation of secrets')
        secret_arn = rs['ARN']

        self.assertEqual(len(secret_arn.rpartition('-')[2]), 6)

        rs = self.secretsmanager_client.get_secret_value(SecretId=secret_name)
        self.assertEqual(rs['Name'], secret_name)
        self.assertEqual(rs['SecretString'], 'my_secret')
        self.assertEqual(rs['ARN'], secret_arn)
        self.assertTrue(isinstance(rs['CreatedDate'], datetime))

        rs = self.secretsmanager_client.get_secret_value(SecretId=secret_arn)
        self.assertEqual(rs['Name'], secret_name)
        self.assertEqual(rs['SecretString'], 'my_secret')
        self.assertEqual(rs['ARN'], secret_arn)

        rs = self.secretsmanager_client.get_secret_value(SecretId=secret_arn[:len(secret_arn) - 6])
        self.assertEqual(rs['Name'], secret_name)
        self.assertEqual(rs['SecretString'], 'my_secret')
        self.assertEqual(rs['ARN'], secret_arn)

        rs = self.secretsmanager_client.get_secret_value(SecretId=secret_arn[:len(secret_arn) - 7])
        self.assertEqual(rs['Name'], secret_name)
        self.assertEqual(rs['SecretString'], 'my_secret')
        self.assertEqual(rs['ARN'], secret_arn)

        self.secretsmanager_client.put_secret_value(SecretId=secret_name, SecretString='new_secret')

        rs = self.secretsmanager_client.get_secret_value(SecretId=secret_name)
        self.assertEqual(rs['Name'], secret_name)
        self.assertEqual(rs['SecretString'], 'new_secret')

        # update secret by ARN
        rs = self.secretsmanager_client.update_secret(SecretId=secret_arn, KmsKeyId='test123', Description='d1')
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)
        self.assertEqual(rs['ARN'], secret_arn)

        # clean up
        self.secretsmanager_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)

    def test_call_lists_secrets_multiple_time(self):
        secret_name = 's-%s' % short_uid()
        self.secretsmanager_client.create_secret(
            Name=secret_name, SecretString='my_secret', Description='testing creation of secrets')

        # call list_secrets multiple times
        for i in range(3):
            rs = self.secretsmanager_client.list_secrets()
            secrets = [
                secret for secret in rs['SecretList'] if secret['Name'] == secret_name
            ]
            self.assertEqual(len(secrets), 1)

        # clean up
        self.secretsmanager_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)

    def test_create_multi_secrets(self):
        secret_names = [short_uid(), short_uid(), short_uid()]
        arns = []
        for secret_name in secret_names:
            rs = self.secretsmanager_client.create_secret(
                Name=secret_name,
                SecretString='my_secret_{}'.format(secret_name),
                Description='testing creation of secrets'
            )
            arns.append(rs['ARN'])

        rs = self.secretsmanager_client.list_secrets()
        secrets = {
            secret['Name']: secret['ARN']
            for secret in rs['SecretList'] if secret['Name'] in secret_names
        }

        self.assertEqual(len(secrets.keys()), len(secret_names))
        for arn in arns:
            self.assertIn(arn, secrets.values())

        # clean up
        for secret_name in secret_names:
            self.secretsmanager_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)

    def test_get_random_exclude_characters_and_symbols(self):
        random_password = self.secretsmanager_client.get_random_password(
            PasswordLength=120, ExcludeCharacters='xyzDje@?!.'
        )

        self.assertEqual(120, len(random_password['RandomPassword']))
        self.assertTrue(all([c not in 'xyzDje@?!.' for c in random_password['RandomPassword']]))

    def test_resource_policy(self):
        secret_name = 's-%s' % short_uid()

        self.secretsmanager_client.create_secret(
            Name=secret_name, SecretString='my_secret', Description='testing creation of secrets')

        self.secretsmanager_client.put_resource_policy(
            SecretId=secret_name, ResourcePolicy=json.dumps(RESOURCE_POLICY))

        rs = self.secretsmanager_client.get_resource_policy(SecretId=secret_name)

        policy = json.loads(rs['ResourcePolicy'])

        self.assertEqual(policy['Version'], RESOURCE_POLICY['Version'])
        self.assertEqual(policy['Statement'], RESOURCE_POLICY['Statement'])

        rs = self.secretsmanager_client.delete_resource_policy(SecretId=secret_name)
        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        self.secretsmanager_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
