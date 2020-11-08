import unittest
from localstack.utils.aws import aws_stack


class TestSTSIntegrations(unittest.TestCase):
    def setUp(self):
        self.sts_client = aws_stack.connect_to_service('sts')

    def test_assume_role(self):
        test_role_session_name = 's3-access-example'
        test_role_arn = 'arn:aws:sts::000000000000:role/rd_role'
        response = self.sts_client.assume_role(RoleArn=test_role_arn, RoleSessionName=test_role_session_name)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        if response['AssumedRoleUser']['AssumedRoleId']:
            assume_role_id_parts = response['AssumedRoleUser']['AssumedRoleId'].split(':')
            self.assertEqual(assume_role_id_parts[1], test_role_session_name)

    def test_assume_role_with_web_identity(self):
        test_role_session_name = 'web_token'
        test_role_arn = 'arn:aws:sts::000000000000:role/rd_role'
        test_web_identity_token = 'token'
        response = self.sts_client.assume_role_with_web_identity(RoleArn=test_role_arn,
                                                                RoleSessionName=test_role_session_name,
                                                                WebIdentityToken=test_web_identity_token)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        if response['AssumedRoleUser']['AssumedRoleId']:
            assume_role_id_parts = response['AssumedRoleUser']['AssumedRoleId'].split(':')
            self.assertEqual(assume_role_id_parts[1], test_role_session_name)

    def test_get_federation_token(self):
        token_name = 'TestName'
        response = self.sts_client.get_federation_token(Name=token_name)

        self.assertTrue(response['Credentials'])
        self.assertTrue(response['Credentials']['SecretAccessKey'])
        self.assertTrue(response['Credentials']['SessionToken'])
        self.assertTrue(response['Credentials']['Expiration'])
        federated_user_info = response['FederatedUser']['FederatedUserId'].split(':')
        self.assertEqual(federated_user_info[1], token_name)
