from localstack.aws.api.es import CreateElasticsearchDomainRequest
from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns, aws_stack
from localstack.utils.collections import convert_to_typed_dict


def es_add_tags_params(params, **kwargs):
    es_arn = arns.es_domain_arn(params.get("DomainName"))
    tags = params.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Elasticsearch::Domain"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        domain_name = self._domain_name()
        if attribute == "Arn":
            return arns.elasticsearch_domain_arn(domain_name)
        return domain_name

    def get_cfn_attribute(self, attribute_name):
        if attribute_name == "DomainArn":
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
        domain_name = self.resolve_refs_recursively(stack_name, domain_name, resources)
        return aws_stack.connect_to_service("es").describe_elasticsearch_domain(
            DomainName=domain_name
        )

    def _domain_name(self):
        return self.props.get("DomainName") or self.logical_resource_id

    @staticmethod
    def get_deploy_templates():
        def _create_params(params, **kwargs):
            result = convert_to_typed_dict(CreateElasticsearchDomainRequest, params)
            result = remove_none_values(result)
            cluster_config = result.get("ElasticsearchClusterConfig")
            if isinstance(cluster_config, dict):
                # set defaults required for boto3 calls
                cluster_config.setdefault("DedicatedMasterType", "m3.medium.elasticsearch")
                cluster_config.setdefault("WarmType", "ultrawarm1.medium.elasticsearch")
            return result

        return {
            "create": [
                {
                    "function": "create_elasticsearch_domain",
                    "parameters": _create_params,
                },
                {"function": "add_tags", "parameters": es_add_tags_params},
            ],
            "delete": {
                "function": "delete_elasticsearch_domain",
                "parameters": {"DomainName": "DomainName"},
            },
        }
