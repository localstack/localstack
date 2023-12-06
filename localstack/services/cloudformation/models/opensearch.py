from localstack.aws.api.opensearch import (
    CreateDomainRequest,
    OpenSearchPartitionInstanceType,
    OpenSearchWarmPartitionInstanceType,
)
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    generate_default_name,
    remove_none_values,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns
from localstack.utils.collections import convert_to_typed_dict


# OpenSearch still uses "es" ARNs
# See examples in:
# https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-opensearchservice-domain.html
def opensearch_add_tags_params(
    account_id: str,
    region_name: str,
    properties: dict,
    logical_resource_id: str,
    resource: dict,
    stack_name: str,
):
    es_arn = arns.elasticsearch_domain_arn(properties.get("DomainName"), account_id, region_name)
    tags = properties.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class OpenSearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::OpenSearchService::Domain"

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).opensearch.describe_domain(DomainName=domain_name)

    def _domain_name(self):
        return self.props.get("DomainName") or self.logical_resource_id

    @staticmethod
    def add_defaults(resource, stack_name: str):
        domain_name = resource.get("Properties", {}).get("DomainName")
        if not domain_name:
            # name must have a minimum length of 3 and a maximum length of 28
            # only lower case is valid for domain name, pattern: [a-z][a-z0-9\-]+
            resource["Properties"]["DomainName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            ).lower()[0:28]

    @staticmethod
    def get_deploy_templates():
        def _create_params(
            account_id: str,
            region_name: str,
            properties: dict,
            logical_resource_id: str,
            resource: dict,
            stack_name: str,
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

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["PhysicalResourceId"] = result["DomainStatus"]["DomainName"]
            resource["Properties"]["DomainEndpoint"] = result["DomainStatus"]["Endpoint"]

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
