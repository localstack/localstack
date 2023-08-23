from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import params_list_to_dict
from localstack.services.cloudformation.service_models import GenericBaseModel


class ResourceGroupsGroup(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::ResourceGroups::Group"

    def fetch_state(self, stack_name, resources):
        client = connect_to(
            aws_access_key_id=self.account_id, region_name=self.region_name
        ).resource_groups
        result = client.list_groups().get("Groups", [])
        result = [g for g in result if g["Name"] == self.props["Name"]]
        return (result or [None])[0]

    @classmethod
    def get_deploy_templates(cls):
        def _handle_result(
            account_id: str,
            region_name: str,
            result: dict,
            logical_resource_id: str,
            resource: dict,
        ):
            resource["Properties"]["Arn"] = result["Group"]["GroupArn"]
            resource["PhysicalResourceId"] = result["Group"]["Name"]

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
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_group", "parameters": {"Group": "Name"}},
        }
