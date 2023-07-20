from localstack.aws.connect import connect_to
from localstack.services.cloudformation.deployment_utils import (
    merge_parameters,
    params_dict_to_list,
    select_parameters,
)
from localstack.services.cloudformation.service_models import GenericBaseModel
from localstack.utils.collections import select_attributes
from localstack.utils.common import short_uid


class SSMParameter(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::Parameter"

    def fetch_state(self, stack_name, resources):
        param_name = self.props.get("Name") or self.logical_resource_id
        return connect_to().ssm.get_parameter(Name=param_name)["Parameter"]

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
        def _handle_result(result, logical_resource_id, resource):
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
        maintenance_windows = connect_to().ssm.describe_maintenance_windows()["WindowIdentities"]
        for maintenance_window in maintenance_windows:
            if maintenance_window["WindowId"] == self.physical_resource_id:
                return maintenance_window

    @staticmethod
    def get_deploy_templates():
        def _delete_window(logical_resource_id, resource, stack_name):
            connect_to().ssm.delete_maintenance_window(WindowId=resource["PhysicalResourceId"])

        def _handle_result(result, logical_resource_id, resource):
            resource["PhysicalResourceId"] = result["WindowId"]

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
                "result_handler": _handle_result,
            },
            "delete": {"function": _delete_window},
        }


class SSMMaintenanceWindowTarget(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::MaintenanceWindowTarget"

    def fetch_state(self, stack_name, resources):
        targets = connect_to().ssm.describe_maintenance_window_targets(
            WindowId=self.props.get("WindowId")
        )["Targets"]
        targets = [
            target for target in targets if target["WindowTargetId"] == self.physical_resource_id
        ]
        return targets[0] if targets else None

    @staticmethod
    def get_deploy_templates():
        def _delete_window_target(logical_resource_id, resource, stack_name):
            connect_to().ssm.deregister_target_from_maintenance_window(
                WindowId=resource["Properties"]["WindowId"],
                WindowTargetId=resource["PhysicalResourceId"],
            )

        def _handle_result(result, logical_resource_id, resource):
            resource["PhysicalResourceId"] = result["WindowTargetId"]

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
                "result_handler": _handle_result,
            },
            "delete": {"function": _delete_window_target},
        }


class SSMMaintenanceTask(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::MaintenanceWindowTask"

    def fetch_state(self, stack_name, resources):
        return connect_to().ssm.describe_maintenance_window_task(
            WindowTaskId=self.props.get("WindowTaskId")
        )["WindowTaskId"]

    @staticmethod
    def get_deploy_templates():
        def _delete_window_task(logical_resource_id, resource, stack_name):
            connect_to().ssm.deregister_task_from_maintenance_window(
                WindowId=resource["Properties"]["WindowId"],
                WindowTaskId=resource["PhysicalResourceId"],
            )

        def _handle_result(result, logical_resource_id, resource):
            resource["PhysicalResourceId"] = result["WindowTaskId"]

        def _params(properties, logical_resource_id, resource_def, stack_name):
            kwargs = {
                "Description": properties.get("Description"),
                "Name": properties.get("Name"),
                "OwnerInformation": properties.get("OwnerInformation"),
                "Priority": properties.get("Priority"),
                "ServiceRoleArn": properties.get("ServiceRoleArn"),
                "Targets": properties.get("Targets"),
                "TaskArn": properties.get("TaskArn"),
                "TaskParameters": properties.get("TaskParameters"),
                "TaskType": properties.get("TaskType"),
                "WindowId": properties.get("WindowId"),
            }

            if invocation_params := properties.get("TaskInvocationParameters"):
                task_type_map = {
                    "MaintenanceWindowAutomationParameters": "Automation",
                    "MaintenanceWindowLambdaParameters": "Lambda",
                    "MaintenanceWindowRunCommandParameters": "RunCommand",
                    "MaintenanceWindowStepFunctionsParameters": "StepFunctions",
                }
                kwargs["TaskInvocationParameters"] = {
                    task_type_map[k]: v for k, v in invocation_params.items()
                }

            return kwargs

        return {
            "create": {
                "function": "register_task_with_maintenance_window",
                "parameters": _params,
                "result_handler": _handle_result,
            },
            "delete": {"function": _delete_window_task},
        }


class SSMPatchBaseline(GenericBaseModel):
    @staticmethod
    def cloudformation_type():
        return "AWS::SSM::PatchBaseline"

    def fetch_state(self, stack_name, resources):
        patches = connect_to().ssm.describe_patch_baselines()["BaselineIdentities"]
        for patch in patches:
            if patch["BaselineId"] == self.physical_resource_id:
                return patch

    @staticmethod
    def get_deploy_templates():
        def _delete_patch_baseline(logical_resource_id, resource, stack_name):
            connect_to().ssm.delete_patch_baseline(BaselineId=resource["PhysicalResourceId"])

        def _handle_result(result, logical_resource_id, resource):
            resource["PhysicalResourceId"] = result["BaselineId"]

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
                "result_handler": _handle_result,
            },
            "delete": {"function": _delete_patch_baseline},
        }
