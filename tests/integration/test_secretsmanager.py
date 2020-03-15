import unittest

from datetime import datetime
from localstack.utils.aws import aws_stack

TEST_SECRET_NAME_1 = 'test_secret_put'
TEST_SECRET_NAME_2 = 'test_secret_2nd'


class SecretsManagerTest(unittest.TestCase):
    def setUp(self):
        self.secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

    def test_create_secret(self):
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
