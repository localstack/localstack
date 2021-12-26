import unittest

from localstack.utils.aws import aws_stack


class TestRGSAIntegrations(unittest.TestCase):
    def setUp(self):
        self.rgsa_client = aws_stack.create_external_boto_client("resourcegroupstaggingapi")
        self.ec2_client = aws_stack.create_external_boto_client("ec2")

    def test_get_resources(self):
        vpc = self.ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        self.ec2_client.create_tags(
            Resources=[vpc.get("Vpc").get("VpcId")],
            Tags=[{"Key": "test", "Value": "test"}],
        )

        def assert_response(resp):
            results = resp.get("ResourceTagMappingList", [])
            self.assertEqual(1, len(results))
            self.assertEqual([{"Key": "test", "Value": "test"}], results[0].get("Tags"))

        resp = self.rgsa_client.get_resources(ResourceTypeFilters=["ec2"])
        assert_response(resp)
