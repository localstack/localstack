from localstack.aws.api.opensearch import (
    CreateDomainRequest,
    OpenSearchPartitionInstanceType,
    OpenSearchWarmPartitionInstanceType,
)
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns
from localstack.utils.collections import convert_to_typed_dict


# OpenSearch still uses "es" ARNs
# See examples in:
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html
def opensearch_add_tags_params(
    properties: dict, logical_resource_id: str, resource: dict, stack_name: str
):
    es_arn = arns.es_domain_arn(properties.get("DomainName"))
    tags = properties.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class OpenSearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::OpenSearchService::Domain"

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        return connect_to().opensearch.describe_domain(DomainName=domain_name)

    def _domain_name(self):
        return self.props.get("DomainName") or self.logical_resource_id

    @staticmethod
    def get_deploy_templates():
        def _create_params(
            properties: dict, logical_resource_id: str, resource: dict, stack_name: str
        ):
            properties = remove_none_values(properties)
            result = convert_to_typed_dict(CreateDomainRequest, properties)
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

        def _handle_result(result: dict, logical_resource_id: str, resource: dict):
            resource["PhysicalResourceId"] = result["DomainStatus"]["DomainName"]

        return {
            "create": [
                {
                    "function": "create_domain",
                    "parameters": _create_params,
                    "result_handler": _handle_result,
                },
                {"function": "add_tags", "parameters": opensearch_add_tags_params},
            ],
            "delete": {
                "function": "delete_domain",
                "parameters": {"DomainName": "DomainName"},
            },
        }
