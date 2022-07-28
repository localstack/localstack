from localstack.services.cloudformation.deployment_utils import params_list_to_dict
from localstack.services.cloudformation.service_models import REF_ARN_ATTRS, GenericBaseModel
from localstack.utils.aws import aws_stack


class ResourceGroupsGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ResourceGroups::Group"

    def fetch_state(self, stack_name, resources):
        client = aws_stack.connect_to_service("resource-groups")
        result = client.list_groups().get("Groups", [])
        result = [g for g in result if g["Name"] == self.props["Name"]]
        return (result or [None])[0]

    def get_physical_resource_id(self, attribute=None, **kwargs):
        if attribute in REF_ARN_ATTRS:
            return self.props.get("GroupArn")
        return self.props.get("Name")

    @classmethod
    def get_deploy_templates(cls):
        return {
            "create": {
                "function": "create_group",
                "parameters": {
                    "Name": "Name",
                    "Description": "Description",
                    "ResourceQuery": "ResourceQuery",
                    "Configuration": "Configuration",
                    "Tags": params_list_to_dict("Tags"),
                },
            },
            "delete": {"function": "delete_group", "parameters": {"Group": "Name"}},
        }
