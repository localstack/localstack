from localstack.aws.api.opensearch import (
    CreateDomainRequest,
    OpenSearchPartitionInstanceType,
    OpenSearchWarmPartitionInstanceType,
)
from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns, aws_stack
from localstack.utils.collections import convert_to_typed_dict


# OpenSearch still uses "es" ARNs
# See examples in:
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html
def opensearch_add_tags_params(params, **kwargs):
    es_arn = arns.es_domain_arn(params.get("DomainName"))
    tags = params.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class OpenSearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::OpenSearchService::Domain"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        domain_name = self._domain_name()
        if attribute == "Arn":
            # As mentioned above, OpenSearch still uses "es" ARNs
            return arns.elasticsearch_domain_arn(domain_name)
        return domain_name

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service("opensearch").describe_domain(DomainName=domain_name)

    def _domain_name(self):
        return self.props.get("DomainName") or self.logical_resource_id

    @staticmethod
    def get_deploy_templates():
        def _create_params(params, **kwargs):
            params = remove_none_values(params)
            result = convert_to_typed_dict(CreateDomainRequest, params)
            cluster_config = result.get("ClusterConfig")
            if isinstance(cluster_config, dict):
                # set defaults required for boto3 calls
                cluster_config.setdefault(
                    "DedicatedMasterType", OpenSearchPartitionInstanceType.m3_medium_search
                )
                cluster_config.setdefault(
                    "WarmType", OpenSearchWarmPartitionInstanceType.ultrawarm1_medium_search
                )
            return result

        return {
            "create": [
                {
                    "function": "create_domain",
                    "parameters": _create_params,
                },
                {"function": "add_tags", "parameters": opensearch_add_tags_params},
            ],
            "delete": {
                "function": "delete_domain",
                "parameters": {"DomainName": "DomainName"},
            },
        }
