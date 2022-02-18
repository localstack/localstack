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
