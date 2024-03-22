from localstack.testing.pytest import markers


class TestRGSAIntegrations:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(paths=["$..PaginationToken"])
    def test_get_resources(self, aws_client, cleanups, snapshot):
        vpc = aws_client.ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpd_id = vpc.get("Vpc").get("VpcId")

        snapshot.add_transformers_list([snapshot.transform.key_value("ResourceARN", "ARN")])
        cleanups.append(lambda: aws_client.ec2.delete_vpc(VpcId=vpd_id))

        tags = [{"Key": "test", "Value": "test"}]

        aws_client.ec2.create_tags(
            Resources=[vpc.get("Vpc").get("VpcId")],
            Tags=tags,
        )
        resp = aws_client.resourcegroupstaggingapi.get_resources(
            TagFilters=[{"Key": "test", "Values": ["test"]}]
        )
        snapshot.match("get_resources", resp)
