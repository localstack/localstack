import unittest
from localstack.utils.aws import aws_stack


class SSMTest(unittest.TestCase):

    def test_describe_parameters(self):
        ssm_client = aws_stack.connect_to_service('ssm')

        response = ssm_client.describe_parameters()
        self.assertIn('Parameters', response)
        self.assertIsInstance(response['Parameters'], list)

    def test_put_parameters(self):
        ssm_client = aws_stack.connect_to_service('ssm')

        ssm_client.put_parameter(
            Name='test_put',
            Description='test',
            Value='123',
            Type='String',
        )

        self._assert('test_put', 'test_put')
        self._assert('/test_put', 'test_put')

    def test_hierarchical_parameter(self):
        ssm_client = aws_stack.connect_to_service('ssm')

        ssm_client.put_parameter(
            Name='/a/b/c',
            Value='123',
            Type='String',
        )

        self._assert('/a/b/c', '/a/b/c')
        self._assert('/a//b//c', '/a/b/c')
        self._assert('a/b//c', '/a/b/c')

    def test_get_paramter(self):
        ssm_client = aws_stack.connect_to_service('ssm')
        sec_client = aws_stack.connect_to_service('secretsmanager')

        secret_name = 'test_secret'
        sec_client.create_secret(
            Name=secret_name,
            SecretString='my_secret',
            Description='testing creation of secrets'
        )

        result = ssm_client.get_parameter(Name='/aws/reference/secretsmanager/{0}'.format(secret_name))

        self.assertEqual(result.get('Parameter').get('Name'), '/aws/reference/secretsmanager/{0}'.format(secret_name))
        self.assertEqual(result.get('Parameter').get('Value'), 'my_secret')

    def _assert(self, search_name, param_name):
        ssm_client = aws_stack.connect_to_service('ssm')

        def do_assert(result):
            self.assertGreater(len(result), 0)
            self.assertEqual(result[0]['Name'], param_name)
            self.assertEqual(result[0]['Value'], '123')

        response = ssm_client.get_parameter(Name=search_name)
        do_assert([response['Parameter']])

        response = ssm_client.get_parameters(Names=[search_name])
        do_assert(response['Parameters'])
