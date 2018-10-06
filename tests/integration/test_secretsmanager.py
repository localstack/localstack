import unittest
from localstack.utils.aws import aws_stack


class SecretsManagerTest(unittest.TestCase):
    def test_create_secret(self):
        secretsmanager_client = aws_stack.connect_to_service('secretsmanager')

        secretsmanager_client.create_secret(
            Name='test_secret_put',
            SecretString='mysecret',
            Description='testing creation of secrets'
        )

        response = secretsmanager_client.get_secret_value(
            SecretId='test_secret_put',
        )

        assert response['Name'] == 'test_secret_put'
        assert response['SecretString'] == 'mysecret'
