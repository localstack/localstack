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
        def _handle_result(result, resource_id, resources, resource_type):
            resource = resources[resource_id]
            resource["PhysicalResourceId"] = resource["Properties"]["Name"]

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
                "result_handler": _handle_result,
            },
            "delete": {"function": "delete_parameter", "parameters": ["Name"]},
        }


class SSMMaintenanceWindow(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::MaintenanceWindow"

    def fetch_state(self, stack_name, resources):
        if not self.physical_resource_id:
            return None
        maintenance_windows = aws_stack.connect_to_service("ssm").describe_maintenance_windows()[
            "WindowIdentities"
        ]
        for maintenance_window in maintenance_windows:
            if maintenance_window["WindowId"] == self.physical_resource_id:
                return maintenance_window

    @staticmethod
    def get_deploy_templates():
        def _delete_window(resource_id, resources, resource_type, func, stack_name):
            ssm_client = aws_stack.connect_to_service("ssm")
            ssm_client.delete_maintenance_window(
                WindowId=resources[resource_id]["PhysicalResourceId"]
            )

        def _store_window_id(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["WindowId"]

        return {
            "create": {
                "function": "create_maintenance_window",
                "parameters": select_parameters(
                    "AllowUnassociatedTargets",
                    "Cutoff",
                    "Duration",
                    "Name",
                    "Schedule",
                    "ScheduleOffset",
                    "ScheduleTimezone",
                    "StartDate",
                    "EndDate",
                    "Description",
                    "Tags",
                ),
                "result_handler": _store_window_id,
            },
            "delete": {"function": _delete_window},
        }


class SSMMaintenanceWindowTarget(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::MaintenanceWindowTarget"

    def fetch_state(self, stack_name, resources):
        return aws_stack.connect_to_service("ssm").describe_maintenance_window_target(
            WindowTargetId=self.props.get("WindowTargetId")
        )["WindowTargetId"]

    @staticmethod
    def get_deploy_templates():
        def _delete_window_target(resource_id, resources, resource_type, func, stack_name):
            ssm_client = aws_stack.connect_to_service("ssm")
            ssm_client.deregister_target_from_maintenance_window(
                WindowId=resources[resource_id]["Properties"]["WindowId"],
                WindowTargetId=resources[resource_id]["PhysicalResourceId"],
            )

        def _store_window_target_id(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["WindowTargetId"]

        return {
            "create": {
                "function": "register_target_with_maintenance_window",
                "parameters": select_parameters(
                    "Description",
                    "Name",
                    "OwnerInformation",
                    "ResourceType",
                    "Targets",
                    "WindowId",
                ),
                "result_handler": _store_window_target_id,
            },
            "delete": {"function": _delete_window_target},
        }


class SSMMaintenanceTask(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::MaintenanceWindowTask"

    def fetch_state(self, stack_name, resources):
        return aws_stack.connect_to_service("ssm").describe_maintenance_window_task(
            WindowTaskId=self.props.get("WindowTaskId")
        )["WindowTaskId"]

    @staticmethod
    def get_deploy_templates():
        def _delete_window_task(resource_id, resources, resource_type, func, stack_name):
            ssm_client = aws_stack.connect_to_service("ssm")
            ssm_client.deregister_task_from_maintenance_window(
                WindowId=resources[resource_id]["Properties"]["WindowId"],
                WindowTaskId=resources[resource_id]["PhysicalResourceId"],
            )

        def _store_window_task_id(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["WindowTaskId"]

        return {
            "create": {
                "function": "register_task_with_maintenance_window",
                "parameters": select_parameters(
                    "Description",
                    "Name",
                    "OwnerInformation",
                    "Priority",
                    "ServiceRoleArn",
                    "Targets",
                    "TaskArn",
                    "TaskInvocationParameters",
                    "TaskParameters",
                    "TaskType",
                    "WindowId",
                ),
                "result_handler": _store_window_task_id,
            },
            "delete": {"function": _delete_window_task},
        }


class SSMPatchBaseline(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::PatchBaseline"

    def fetch_state(self, stack_name, resources):
        return aws_stack.connect_to_service("ssm").describe_patch_baselines(
            BaselineId=self.props.get("BaselineId")
        )["BaselineId"]

    @staticmethod
    def get_deploy_templates():
        def _delete_patch_baseline(resource_id, resources, resource_type, func, stack_name):
            ssm_client = aws_stack.connect_to_service("ssm")
            ssm_client.delete_patch_baseline(
                BaselineId=resources[resource_id]["PhysicalResourceId"]
            )

        def _store_patch_baseline_id(result, resource_id, resources, resource_type):
            resources[resource_id]["PhysicalResourceId"] = result["BaselineId"]

        return {
            "create": {
                "function": "create_patch_baseline",
                "parameters": select_parameters(
                    "OperatingSystem",
                    "Name",
                    "GlobalFilters",
                    "ApprovalRules",
                    "ApprovedPatches",
                    "ApprovedPatchesComplianceLevel",
                    "ApprovedPatchesEnableNonSecurity",
                    "RejectedPatches",
                    "RejectedPatchesAction",
                    "Description",
                    "Sources",
                    "ClientToken",
                    "Tags",
                ),
                "result_handler": _store_patch_baseline_id,
            },
            "delete": {"function": _delete_patch_baseline},
        }
