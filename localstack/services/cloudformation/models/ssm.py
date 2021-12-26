from localstack.services.cloudformation.deployment_utils import (
    merge_parameters,
    params_dict_to_list,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::Parameter"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name") or self.resource_id

    def fetch_state(self, stack_name, resources):
        param_name = self.props.get("Name") or self.resource_id
        param_name = self.resolve_refs_recursively(stack_name, param_name, resources)
        return aws_stack.connect_to_service("ssm").get_parameter(Name=param_name)["Parameter"]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource.get("Properties", {}).get("Name")
        if not name:
            resource["Properties"]["Name"] = f"CFN-{resource['LogicalResourceId']}-{short_uid()}"

    @staticmethod
    def get_deploy_templates():
        return {
            "create": {
                "function": "put_parameter",
                "parameters": merge_parameters(
                    params_dict_to_list("Tags", wrapper="Tags"),
                    select_parameters(
                        "Name",
                        "Type",
                        "Value",
                        "Description",
                        "AllowedPattern",
                        "Policies",
                        "Tier",
                    ),
                ),
                "types": {"Value": str},
            },
            "delete": {"function": "delete_parameter", "parameters": ["Name"]},
        }
