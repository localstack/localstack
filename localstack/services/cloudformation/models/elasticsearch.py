from localstack.aws.api.es import CreateElasticsearchDomainRequest
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns
from localstack.utils.collections import convert_to_typed_dict


def es_add_tags_params(properties: dict, logical_resource_id: str, resource: dict, stack_name: str):
    es_arn = arns.es_domain_arn(properties.get("DomainName"))
    tags = properties.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Elasticsearch::Domain"

    def get_cfn_attribute(self, attribute_name):
        if attribute_name in ["Arn", "DomainArn"]:
            domain_name = self._domain_name()
            return arns.elasticsearch_domain_arn(domain_name)
        if attribute_name == "DomainEndpoint":
            domain_status = self.props.get("DomainStatus", {})
            result = domain_status.get("Endpoint")
            if result:
                return result
        return super(ElasticsearchDomain, self).get_cfn_attribute(attribute_name)

    def fetch_state(self, stack_name, resources):
        domain_name = self._domain_name()
        return connect_to().es.describe_elasticsearch_domain(DomainName=domain_name)

    def _domain_name(self):
        return self.props.get("DomainName") or self.logical_resource_id

    @staticmethod
    def get_deploy_templates():
        def _create_params(
            properties: dict, logical_resource_id: str, resource: dict, stack_name: str
        ):
            result = convert_to_typed_dict(CreateElasticsearchDomainRequest, properties)
            result = remove_none_values(result)
            cluster_config = result.get("ElasticsearchClusterConfig")
            if isinstance(cluster_config, dict):
                # set defaults required for boto3 calls
                cluster_config.setdefault("DedicatedMasterType", "m3.medium.elasticsearch")
                cluster_config.setdefault("WarmType", "ultrawarm1.medium.elasticsearch")
            return result

        def _handle_result(result, resource_id, resources, resource_type):
            resource = resources[resource_id]

            domain_name = resource["Properties"].get("DomainName", resource_id)
            resource["PhysicalResourceId"] = domain_name
            # TODO: wait for resource
            describe_result = connect_to().es.describe_elasticsearch_domain(DomainName=domain_name)[
                "DomainStatus"
            ]
            resource["Properties"]["DomainStatus"] = {"Endpoint": describe_result["Endpoint"]}

        return {
            "create": [
                {
                    "function": "create_elasticsearch_domain",
                    "parameters": _create_params,
                    "result_handler": _handle_result,
                },
                {"function": "add_tags", "parameters": es_add_tags_params},
            ],
            "delete": {
                "function": "delete_elasticsearch_domain",
                "parameters": {"DomainName": "DomainName"},
            },
        }
