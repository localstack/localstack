from localstack.aws.connect import connect_to
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

        ssm_client = connect_to().ssm

        # tag handling
        new_tags = update_config_props.pop("Tags", {})
        current_tags = ssm_client.list_tags_for_resource(
            ResourceType="Parameter", ResourceId=self.props.get("Name")
        )["TagList"]
        current_tags = {tag["Key"]: tag["Value"] for tag in current_tags}

        new_tag_keys = set(new_tags.keys())
        old_tag_keys = set(current_tags.keys())
        potentially_modified_tag_keys = new_tag_keys.intersection(old_tag_keys)
        tag_keys_to_add = new_tag_keys.difference(old_tag_keys)
        tag_keys_to_remove = old_tag_keys.difference(new_tag_keys)

        for tag_key in potentially_modified_tag_keys:
            # also overwrite changed tags
            if new_tags[tag_key] != current_tags[tag_key]:
                tag_keys_to_add.add(tag_key)

        if tag_keys_to_add:
            ssm_client.add_tags_to_resource(
                ResourceType="Parameter",
                ResourceId=self.props.get("Name"),
                Tags=[
                    {"Key": tag_key, "Value": tag_value}
                    for tag_key, tag_value in new_tags.items()
                    if tag_key in tag_keys_to_add
                ],
            )

        if tag_keys_to_remove:
            ssm_client.remove_tags_from_resource(
                ResourceType="Parameter", ResourceId=self.props.get("Name"), Tags=tag_keys_to_remove
            )

        return ssm_client.put_parameter(Overwrite=True, **update_config_props)

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
