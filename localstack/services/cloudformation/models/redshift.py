from localstack.services.cloudformation.deployment_utils import generate_default_name
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
        cluster_id = self.props.get("ClusterIdentifier")
        result = client.describe_clusters(ClusterIdentifier=cluster_id)["Clusters"]
        return (result or [None])[0]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        role_name = resource.get("Properties", {}).get("ClusterIdentifier")
        if not role_name:
            resource["Properties"]["ClusterIdentifier"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

    @staticmethod
    def get_deploy_templates():
        return {"create": {"function": "create_cluster"}}
