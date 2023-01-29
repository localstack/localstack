from localstack.services.cloudformation.deployment_utils import (
    merge_parameters,
    params_dict_to_list,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.aws import aws_stack
from localstack.utils.collections import select_attributes
from localstack.utils.common import short_uid


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::Parameter"

    def get_physical_resource_id(self, attribute=None, **kwargs):
        return self.props.get("Name") or self.logical_resource_id

    def fetch_state(self, stack_name, resources):
        param_name = self.props.get("Name") or self.logical_resource_id
        return aws_stack.connect_to_service("ssm").get_parameter(Name=param_name)["Parameter"]

    @staticmethod
    def add_defaults(resource, stack_name: str):
        name = resource.get("Properties", {}).get("Name")
        if not name:
            resource["Properties"]["Name"] = f"CFN-{resource['LogicalResourceId']}-{short_uid()}"

    def update_resource(self, new_resource, stack_name, resources):
        props = new_resource["Properties"]
        parameters_to_select = [
            "AllowedPattern",
            "DataType",
            "Description",
            "Name",
            "Policies",
            "Tags",
            "Tier",
            "Type",
            "Value",
        ]
        update_config_props = select_attributes(props, parameters_to_select)

        if "Tags" in update_config_props:
            update_config_props["Tags"] = [
                {
                    "Key": k,
                    "Value": v,
                }
                for (k, v) in (update_config_props["Tags"] or {}).items()
            ]

        client = aws_stack.connect_to_service("ssm")
        return client.put_parameter(Overwrite=True, **update_config_props)

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
