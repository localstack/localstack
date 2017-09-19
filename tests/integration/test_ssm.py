import unittest
from localstack.utils.aws import aws_stack


class SSMTest(unittest.TestCase):
    def test_describe_parameters(self):
        ssm_client = aws_stack.connect_to_service('ssm')

        response = ssm_client.describe_parameters()

        assert 'Parameters' in response
        assert isinstance(response['Parameters'], list)

    def test_put_parameters(self):
        ssm_client = aws_stack.connect_to_service('ssm')

        ssm_client.put_parameter(
            Name='test_put',
            Description='test',
            Value='1',
            Type='String',
        )

        response = ssm_client.get_parameters(
            Names=['test_put'],
        )

        assert 'Parameters' in response
        assert len(response['Parameters']) > 0
        assert response['Parameters'][0]['Name'] == 'test_put'
        assert response['Parameters'][0]['Value'] == '1'
