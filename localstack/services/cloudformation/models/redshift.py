from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel


class RedshiftCluster(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Redshift::Cluster"

    def fetch_state(self, stack_name, resources):
        client = connect_to().redshift
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
        def _handle_result(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["Cluster"]["ClusterIdentifier"]

        return {"create": {"function": "create_cluster", "result_handler": _handle_result}}
