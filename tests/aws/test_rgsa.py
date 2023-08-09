from localstack.testing.pytest import markers


class TestRGSAIntegrations:
    @markers.aws.unknown
    def test_get_resources(self, aws_client):
        vpc = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")
        try:
            aws_client.ec2.create_tags(
                Resources=[vpc.get("Vpc").get("VpcId")],
                Tags=[{"Key": "test", "Value": "test"}],
            )

            resp = aws_client.resourcegroupstaggingapi.get_resources(ResourceTypeFilters=["ec2"])
            results = resp.get("ResourceTagMappingList", [])
            assert 1 == len(results)
            assert [{"Key": "test", "Value": "test"}] == results[0].get("Tags")
        finally:
            aws_client.ec2.delete_vpc(VpcId=vpc["Vpc"]["VpcId"])
