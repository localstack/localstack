import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid
from localstack.utils.sync import retry


class TestRedshift:
    @markers.aws.validated
    def test_create_clusters(self, aws_client):
        # create
        cluster_id = f"c-{short_uid()}"
        response = aws_client.redshift.create_cluster(
            ClusterIdentifier=cluster_id,
            NodeType="ra3.xlplus",
            MasterUsername="test",
            MasterUserPassword="testABc123",
            NumberOfNodes=2,
            PubliclyAccessible=False,
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # describe
        clusters = aws_client.redshift.describe_clusters()["Clusters"]
        matching = [c for c in clusters if c["ClusterIdentifier"] == cluster_id]
        assert matching

        # wait until available
        def check_running():
            result = aws_client.redshift.describe_clusters()["Clusters"]
            status = result[0].get("ClusterStatus")
            assert status == "available"
            return result[0]

        retries = 500 if is_aws_cloud() else 60
        sleep = 30 if is_aws_cloud() else 1
        retry(check_running, sleep=sleep, retries=retries)

        # delete
        response = aws_client.redshift.delete_cluster(
            ClusterIdentifier=cluster_id, SkipFinalClusterSnapshot=True
        )
        assert response["ResponseMetadata"]["HTTPStatusCode"] == 200

        # assert that cluster deleted
        def check_deleted():
            with pytest.raises(Exception) as e:
                aws_client.redshift.describe_clusters(ClusterIdentifier=cluster_id)
            assert "ClusterNotFound" in str(e)

        retry(check_deleted, sleep=sleep, retries=retries)

    @markers.aws.manual_setup_required
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
