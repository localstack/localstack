class TestRGSAIntegrations:
    def test_get_resources(self, ec2_client, rgsa_client):
        vpc = ec2_client.create_vpc(CidrBlock="10.0.0.0/16")
        try:
            ec2_client.create_tags(
                Resources=[vpc.get("Vpc").get("VpcId")],
                Tags=[{"Key": "test", "Value": "test"}],
            )

            resp = rgsa_client.get_resources(ResourceTypeFilters=["ec2"])
            results = resp.get("ResourceTagMappingList", [])
            assert 1 == len(results)
            assert [{"Key": "test", "Value": "test"}] == results[0].get("Tags")
        finally:
            ec2_client.delete_vpc(VpcId=vpc["Vpc"]["VpcId"])
