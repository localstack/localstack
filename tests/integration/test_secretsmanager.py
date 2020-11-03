import unittest
import json

from datetime import datetime
from localstack.utils.aws import aws_stack

TEST_SECRET_NAME_1 = 'test_secret_put'
TEST_SECRET_NAME_2 = 'test_secret_2nd'
TEST_SECRET_NAME_3 = 'test_secret_3rd'
RESOURCE_POLICY = {
    'Version': '2012-10-17',
    'Statement': [{
        'Effect': 'Allow',
        'Principal': {
            'AWS': 'arn:aws:iam::123456789012:root'
        },
        'Action': 'secretsmanager:GetSecretValue',
        'Resource': '*'
    }]
}


class SecretsManagerTest(unittest.TestCase):
    def setUp(self):
        self.secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

    def test_create_and_update_secret(self):
        rs = self.secretsmanager_client.create_secret(
            Name=TEST_SECRET_NAME_1,
            SecretString='my_secret',
            Description='testing creation of secrets'
        )

        secret_arn = rs['ARN']

        rs = self.secretsmanager_client.get_secret_value(
            SecretId=TEST_SECRET_NAME_1,
        )

        self.assertEqual(rs['Name'], TEST_SECRET_NAME_1)
        self.assertEqual(rs['SecretString'], 'my_secret')
        self.assertEqual(rs['ARN'], secret_arn)
        self.assertTrue(isinstance(rs['CreatedDate'], datetime))

        self.secretsmanager_client.put_secret_value(
            SecretId=TEST_SECRET_NAME_1,
            SecretString='new_secret'
        )

        rs = self.secretsmanager_client.get_secret_value(
            SecretId=TEST_SECRET_NAME_1,
        )

        self.assertEqual(rs['Name'], TEST_SECRET_NAME_1)
        self.assertEqual(rs['SecretString'], 'new_secret')

        # clean up
        self.secretsmanager_client.delete_secret(
            SecretId=TEST_SECRET_NAME_1,
            ForceDeleteWithoutRecovery=True
        )

    def test_call_lists_secrets_multiple_time(self):
        self.secretsmanager_client.create_secret(
            Name=TEST_SECRET_NAME_2,
            SecretString='my_secret',
            Description='testing creation of secrets'
        )

        # call list_secrets 1st
        rs = self.secretsmanager_client.list_secrets()
        secrets = [
            secret for secret in rs['SecretList'] if secret['Name'] == TEST_SECRET_NAME_2
        ]

        self.assertEqual(len(secrets), 1)
        secret_arn = secrets[0]['ARN']

        # call list_secrets 2nd
        rs = self.secretsmanager_client.list_secrets()
        secrets = [
            secret for secret in rs['SecretList'] if secret['Name'] == TEST_SECRET_NAME_2
        ]

        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0]['ARN'], secret_arn)

        # clean up
        self.secretsmanager_client.delete_secret(
            SecretId=TEST_SECRET_NAME_2,
            ForceDeleteWithoutRecovery=True
        )

    def test_create_multi_secrets(self):
        secret_names = [TEST_SECRET_NAME_1, TEST_SECRET_NAME_2, TEST_SECRET_NAME_3]
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
            self.secretsmanager_client.delete_secret(
                SecretId=secret_name,
                ForceDeleteWithoutRecovery=True
            )

    def test_get_random_exclude_characters_and_symbols(self):
        random_password = self.secretsmanager_client.get_random_password(
            PasswordLength=120, ExcludeCharacters='xyzDje@?!.'
        )

        self.assertEqual(120, len(random_password['RandomPassword']))
        self.assertTrue(all([c not in 'xyzDje@?!.' for c in random_password['RandomPassword']]))

    def test_resource_policy(self):
        self.secretsmanager_client.create_secret(
            Name=TEST_SECRET_NAME_1,
            SecretString='my_secret',
            Description='testing creation of secrets'
        )

        self.secretsmanager_client.put_resource_policy(
            SecretId=TEST_SECRET_NAME_1,
            ResourcePolicy=json.dumps(RESOURCE_POLICY)
        )

        rs = self.secretsmanager_client.get_resource_policy(
            SecretId=TEST_SECRET_NAME_1
        )

        policy = json.loads(rs['ResourcePolicy'])

        self.assertEqual(policy['Version'], RESOURCE_POLICY['Version'])
        self.assertEqual(policy['Statement'], RESOURCE_POLICY['Statement'])

        rs = self.secretsmanager_client.delete_resource_policy(
            SecretId=TEST_SECRET_NAME_1
        )

        self.assertEqual(rs['ResponseMetadata']['HTTPStatusCode'], 200)

        # clean up
        self.secretsmanager_client.delete_secret(
            SecretId=TEST_SECRET_NAME_1,
            ForceDeleteWithoutRecovery=True
        )
