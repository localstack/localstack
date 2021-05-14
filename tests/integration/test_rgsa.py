import unittest
from localstack.utils.aws import aws_stack


class TestRGSAIntegrations(unittest.TestCase):
    def setUp(self):
        self.rgsa_client = aws_stack.connect_to_service('resourcegroupstaggingapi')
        self.ec2_client = aws_stack.connect_to_service('ec2')

    def test_get_resources(self):
        vpc = self.ec2_client.create_vpc(CidrBlock='10.0.0.0/16')
        self.ec2_client.create_tags(Resources=[vpc.get('Vpc').get('VpcId')], Tags=[{'Key': 'test', 'Value': 'test'}])

        def assert_response(resp):
            results = resp.get('ResourceTagMappingList', [])
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0].get('Tags'), [{'Key': 'test', 'Value': 'test'}])
        resp = self.rgsa_client.get_resources(ResourceTypeFilters=['ec2'])
        assert_response(resp)
