from localstack.aws.api.es import CreateElasticsearchDomainRequest
from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import remove_none_values
from localstack.services.cloudformation.provider_utils import generate_default_name
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import arns
from localstack.utils.collections import convert_to_typed_dict
from localstack.utils.sync import poll_condition


def es_add_tags_params(
    account_id: str,
    region_name: str,
    properties: dict,
    logical_resource_id: str,
    resource: dict,
    stack_name: str,
):
    es_arn = arns.es_domain_arn(properties.get("DomainName"), account_id, region_name)
    tags = properties.get("Tags", [])
    return {"ARN": es_arn, "TagList": tags}


class ElasticsearchDomain(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::Elasticsearch::Domain"

    def fetch_state(self, stack_name, resources):
        domain_name = self.props["DomainName"]
        return connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).es.describe_elasticsearch_domain(DomainName=domain_name)

    @staticmethod
    def add_defaults(resource, stack_name: str):
        # TODO: verify
        name = resource.get("Properties", {}).get("DomainName")
        if not name:
            resource["Properties"]["DomainName"] = generate_default_name(
                stack_name, resource["LogicalResourceId"]
            )

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
            result = convert_to_typed_dict(CreateElasticsearchDomainRequest, properties)
            result = remove_none_values(result)
            cluster_config = result.get("ElasticsearchClusterConfig")
            if isinstance(cluster_config, dict):
                # set defaults required for boto3 calls
                cluster_config.setdefault("DedicatedMasterType", "m3.medium.elasticsearch")
                cluster_config.setdefault("WarmType", "ultrawarm1.medium.elasticsearch")
            return result

        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            domain_name = resource["Properties"]["DomainName"]
            resource["PhysicalResourceId"] = domain_name
            resource["Properties"]["DomainEndpoint"] = result["DomainStatus"]["Endpoint"]
            resource["Properties"]["Arn"] = result["DomainStatus"]["ARN"]
            resource["Properties"]["DomainArn"] = result["DomainStatus"]["ARN"]

            # TODO: wait for resource
            poll_condition(
                lambda: connect_to(
                    aws_access_key_id=account_id, region_name=region_name
                ).es.describe_elasticsearch_domain(DomainName=domain_name)["DomainStatus"][
                    "Created"
                ],
                timeout=120,
                interval=1,
            )

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
