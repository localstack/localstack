from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack


class RedshiftCluster(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Redshift::Cluster"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("ClusterIdentifier")

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("redshift")
        cluster_id = self.resolve_refs_recursively(
            stack_name, self.props.get("ClusterIdentifier"), resources
        )
        result = client.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        return (result or [None])[0]

    @staticmethod
    def get_deploy_templates():
        return {"create": {"function": "create_cluster"}}
