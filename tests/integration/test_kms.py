import unittest
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack


class KMSTest(unittest.TestCase):

    def test_create_key(self):
        client = aws_stack.connect_to_service('kms')

        response = client.list_keys()
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        keys_before = response['Keys']

        response = client.create_key(
            Policy='policy1',
            Description='test key 123',
            KeyUsage='ENCRYPT_DECRYPT')
        self.assertEqual(response['ResponseMetadata']['HTTPStatusCode'], 200)
        key_id = response['KeyMetadata']['KeyId']

        response = client.list_keys()
        self.assertEqual(len(response['Keys']), len(keys_before) + 1)

        response = client.describe_key(KeyId=key_id)['KeyMetadata']
        self.assertEqual(response['KeyId'], key_id)
        self.assertIn(':%s:' % config.DEFAULT_REGION, response['Arn'])
        self.assertIn(':%s:' % TEST_AWS_ACCOUNT_ID, response['Arn'])
