import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


class TestRedshift:
    @markers.aws.unknown
    def test_create_clusters(self, aws_client):
        # create
        cluster_id = f"c={short_uid()}"
        response = aws_client.redshift.create_cluster(
            ClusterIdentifier=cluster_id,
            NodeType="t1",
            MasterUsername="test",
            MasterUserPassword="test",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # describe
        clusters = aws_client.redshift.describe_clusters()["Clusters"]
        matching = [c for c in clusters if c["ClusterIdentifier"] == cluster_id]
        assert matching

        # delete
        response = aws_client.redshift.delete_cluster(ClusterIdentifier=cluster_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # assert that cluster deleted
        with pytest.raises(Exception) as e:
            aws_client.redshift.describe_clusters(ClusterIdentifier=cluster_id)
        assert "ClusterNotFound" in str(e)

    @markers.aws.validated
    def test_cluster_security_groups(self, snapshot, aws_client):
        # Note: AWS parity testing not easily possible with our account, due to error message
        #  "VPC-by-Default customers cannot use cluster security groups"

        group_name = f"g-{short_uid()}"
        aws_client.redshift.create_cluster_security_group(
            ClusterSecurityGroupName=group_name, Description="test 123"
        )

        cidr_ip = "192.168.100.101/32"
        aws_client.redshift.authorize_cluster_security_group_ingress(
            ClusterSecurityGroupName=group_name, CIDRIP=cidr_ip
        )

        result = aws_client.redshift.describe_cluster_security_groups(
            ClusterSecurityGroupName=group_name
        )
        groups = result.get("ClusterSecurityGroups", [])
        assert len(groups) == 1
        assert groups[0].get("IPRanges")
        assert groups[0]["IPRanges"][0]["Status"] == "authorized"
        assert groups[0]["IPRanges"][0]["CIDRIP"] == cidr_ip
