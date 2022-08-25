import pytest

from localstack.utils.common import short_uid


class TestRedshift:
    def test_create_clusters(self, redshift_client):

        # create
        cluster_id = f"c={short_uid()}"
        response = redshift_client.create_cluster(
            ClusterIdentifier=cluster_id,
            NodeType="t1",
            MasterUsername="test",
            MasterUserPassword="test",
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # describe
        clusters = redshift_client.describe_clusters()["Clusters"]
        matching = [c for c in clusters if c["ClusterIdentifier"] == cluster_id]
        assert matching

        # delete
        response = redshift_client.delete_cluster(ClusterIdentifier=cluster_id)
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # assert that cluster deleted
        with pytest.raises(Exception) as e:
            redshift_client.describe_clusters(ClusterIdentifier=cluster_id)
        assert "ClusterNotFound" in str(e)

    def test_cluster_security_groups(self, redshift_client, snapshot):
        # Note: AWS parity testing not easily possible with our account, due to error message
        #  "VPC-by-Default customers cannot use cluster security groups"

        group_name = f"g-{short_uid()}"
        redshift_client.create_cluster_security_group(
            ClusterSecurityGroupName=group_name, Description="test 123"
        )

        cidr_ip = "192.168.100.101/32"
        redshift_client.authorize_cluster_security_group_ingress(
            ClusterSecurityGroupName=group_name, CIDRIP=cidr_ip
        )

        result = redshift_client.describe_cluster_security_groups(
            ClusterSecurityGroupName=group_name
        )
        groups = result.get("ClusterSecurityGroups", [])
        assert len(groups) == 1
        assert groups[0].get("IPRanges")
        assert groups[0]["IPRanges"][0]["Status"] == "authorized"
        assert groups[0]["IPRanges"][0]["CIDRIP"] == cidr_ip
