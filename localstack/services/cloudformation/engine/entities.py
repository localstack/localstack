import logging
from typing import Optional, TypedDict

from localstack.aws.api.cloudformation import Capability, ChangeSetType, Parameter
from localstack.services.cloudformation.engine.parameters import (
    StackParameter,
    convert_stack_parameters_to_list,
    strip_parameter_type,
)
from localstack.utils.aws import arns
from localstack.utils.collections import select_attributes
from localstack.utils.json import clone_safe
from localstack.utils.objects import recurse_object
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)


class StackSet:
    """A stack set contains multiple stack instances."""

    # FIXME: confusing name. metadata is the complete incoming request object
    def __init__(self, metadata: dict):
        self.metadata = metadata
        # list of stack instances
        self.stack_instances = []
        # maps operation ID to stack set operation details
        self.operations = {}

    @property
    def stack_set_name(self):
        return self.metadata.get("StackSetName")


class StackInstance:
    """A stack instance belongs to a stack set and is specific to a region / account ID."""

    # FIXME: confusing name. metadata is the complete incoming request object
    def __init__(self, metadata: dict):
        self.metadata = metadata
        # reference to the deployed stack belonging to this stack instance
        self.stack = None


class StackMetadata(TypedDict):
    StackName: str
    Capabilities: list[Capability]
    ChangeSetName: Optional[str]
    ChangSetType: Optional[ChangeSetType]
    Parameters: list[Parameter]


class StackTemplate(TypedDict):
    StackName: str
    ChangeSetName: Optional[str]
    Outputs: dict
    Resources: dict


# TODO: remove metadata (flatten into individual fields)
class Stack:
    def __init__(
        self,
        metadata: Optional[StackMetadata] = None,
        template: Optional[StackTemplate] = None,
        template_body: Optional[str] = None,
    ):
        if template is None:
            template = {}

        self.resolved_outputs = list()  # TODO
        self.resolved_parameters: dict[str, StackParameter] = {}
        self.resolved_conditions: dict[str, bool] = {}

        self.metadata = metadata or {}
        self.template = template or {}
        self.template_body = template_body
        self._template_raw = clone_safe(self.template)
        self.template_original = clone_safe(self.template)
        # initialize resources
        for resource_id, resource in self.template_resources.items():
            resource["LogicalResourceId"] = self.template_original["Resources"][resource_id][
                "LogicalResourceId"
            ] = (resource.get("LogicalResourceId") or resource_id)
        # initialize stack template attributes
        stack_id = self.metadata.get("StackId") or arns.cloudformation_stack_arn(
            self.stack_name, short_uid()
        )
        self.template["StackId"] = self.metadata["StackId"] = stack_id
        self.template["Parameters"] = self.template.get("Parameters") or {}
        self.template["Outputs"] = self.template.get("Outputs") or {}
        self.template["Conditions"] = self.template.get("Conditions") or {}
        # initialize metadata
        self.metadata["Parameters"] = self.metadata.get("Parameters") or []
        self.metadata["StackStatus"] = "CREATE_IN_PROGRESS"
        self.metadata["CreationTime"] = self.metadata.get("CreationTime") or timestamp_millis()
        self.metadata["LastUpdatedTime"] = self.metadata["CreationTime"]
        self.metadata.setdefault("Description", self.template.get("Description"))
        self.metadata.setdefault("RollbackConfiguration", {})
        self.metadata.setdefault("DisableRollback", False)
        self.metadata.setdefault("EnableTerminationProtection", False)
        # maps resource id to resource state
        self._resource_states = {}
        # list of stack events
        self.events = []
        # list of stack change sets
        self.change_sets = []
        # self.evaluated_conditions = {}

    def set_resolved_parameters(self, resolved_parameters: dict[str, StackParameter]):
        self.resolved_parameters = resolved_parameters
        if resolved_parameters:
            self.metadata["Parameters"] = list(resolved_parameters.values())

    def set_resolved_stack_conditions(self, resolved_conditions: dict[str, bool]):
        self.resolved_conditions = resolved_conditions

    def describe_details(self):
        attrs = [
            "StackId",
            "StackName",
            "Description",
            "StackStatusReason",
            "StackStatus",
            "Capabilities",
            "ParentId",
            "RootId",
            "RoleARN",
            "CreationTime",
            "DeletionTime",
            "LastUpdatedTime",
            "ChangeSetId",
            "RollbackConfiguration",
            "DisableRollback",
            "EnableTerminationProtection",
            "DriftInformation",
        ]
        result = select_attributes(self.metadata, attrs)
        result["Tags"] = self.tags
        outputs = self.resolved_outputs
        if outputs:
            result["Outputs"] = outputs
        stack_parameters = convert_stack_parameters_to_list(self.resolved_parameters)
        if stack_parameters:
            result["Parameters"] = [strip_parameter_type(sp) for sp in stack_parameters]
        if not result.get("DriftInformation"):
            result["DriftInformation"] = {"StackDriftStatus": "NOT_CHECKED"}
        for attr in ["Tags", "NotificationARNs"]:
            result.setdefault(attr, [])
        return result

    def set_stack_status(self, status: str, status_reason: Optional[str] = None):
        self.metadata["StackStatus"] = status
        if "FAILED" in status:
            self.metadata["StackStatusReason"] = status_reason or "Deployment failed"
        self.add_stack_event(
            self.stack_name, self.stack_id, status, status_reason=status_reason or ""
        )

    def set_time_attribute(self, attribute, new_time=None):
        self.metadata[attribute] = new_time or timestamp_millis()

    def add_stack_event(
        self,
        resource_id: str = None,
        physical_res_id: str = None,
        status: str = "",
        status_reason: str = "",
    ):
        resource_id = resource_id or self.stack_name
        physical_res_id = physical_res_id or self.stack_id
        resource_type = (
            self.template.get("Resources", {})
            .get(resource_id, {})
            .get("Type", "AWS::CloudFormation::Stack")
        )

        event = {
            "EventId": long_uid(),
            "Timestamp": timestamp_millis(),
            "StackId": self.stack_id,
            "StackName": self.stack_name,
            "LogicalResourceId": resource_id,
            "PhysicalResourceId": physical_res_id,
            "ResourceStatus": status,
            "ResourceType": resource_type,
        }

        if status_reason:
            event["ResourceStatusReason"] = status_reason

        self.events.insert(0, event)

    def set_resource_status(self, resource_id: str, status: str):
        """Update the deployment status of the given resource ID and publish a corresponding stack event."""
        physical_res_id = self.resources.get(resource_id, {}).get("PhysicalResourceId")
        self._set_resource_status_details(resource_id, physical_res_id=physical_res_id)
        state = self.resource_states.setdefault(resource_id, {})
        state["PreviousResourceStatus"] = state.get("ResourceStatus")
        state["ResourceStatus"] = status
        state["LastUpdatedTimestamp"] = timestamp_millis()
        self.add_stack_event(resource_id, physical_res_id, status)

    def _set_resource_status_details(self, resource_id: str, physical_res_id: str = None):
        """Helper function to ensure that the status details for the given resource ID are up-to-date."""
        resource = self.resources.get(resource_id)
        if resource is None or resource.get("Type") == "Parameter":
            # make sure we delete the states for any non-existing/deleted resources
            self._resource_states.pop(resource_id, None)
            return
        state = self._resource_states.setdefault(resource_id, {})
        attr_defaults = (
            ("LogicalResourceId", resource_id),
            ("PhysicalResourceId", physical_res_id),
        )
        for res in [resource, state]:
            for attr, default in attr_defaults:
                res[attr] = res.get(attr) or default
        state["StackName"] = state.get("StackName") or self.stack_name
        state["StackId"] = state.get("StackId") or self.stack_id
        state["ResourceType"] = state.get("ResourceType") or self.resources[resource_id].get("Type")
        state["Timestamp"] = timestamp_millis()
        return state

    def resource_status(self, resource_id: str):
        result = self._lookup(self.resource_states, resource_id)
        return result

    def latest_template_raw(self):
        if self.change_sets:
            return self.change_sets[-1]._template_raw
        return self._template_raw

    @property
    def resource_states(self):
        for resource_id in list(self._resource_states.keys()):
            self._set_resource_status_details(resource_id)
        return self._resource_states

    @property
    def stack_name(self):
        return self.metadata["StackName"]

    @property
    def stack_id(self):
        return self.metadata["StackId"]

    @property
    def resources(self):
        """Return dict of resources"""
        return dict(self.template_resources)

    @property
    def template_resources(self):
        return self.template.setdefault("Resources", {})

    @property
    def tags(self):
        return self.metadata.get("Tags", [])

    @property
    def imports(self):
        def _collect(o, **kwargs):
            if isinstance(o, dict):
                import_val = o.get("Fn::ImportValue")
                if import_val:
                    result.add(import_val)
            return o

        result = set()
        recurse_object(self.resources, _collect)
        return result

    @property
    def template_parameters(self):
        return self.template["Parameters"]

    @property
    def conditions(self):
        """Returns the (mutable) dict of stack conditions."""
        return self.template.setdefault("Conditions", {})

    @property
    def mappings(self):
        """Returns the (mutable) dict of stack mappings."""
        return self.template.setdefault("Mappings", {})

    @property
    def outputs(self):
        """Returns the (mutable) dict of stack outputs."""
        return self.template.setdefault("Outputs", {})

    @property
    def status(self):
        return self.metadata["StackStatus"]

    @property
    def resource_types(self):
        return [r.get("Type") for r in self.template_resources.values()]

    def resource(self, resource_id):
        return self._lookup(self.resources, resource_id)

    def _lookup(self, resource_map, resource_id):
        resource = resource_map.get(resource_id)
        if not resource:
            raise Exception(
                'Unable to find details for resource "%s" in stack "%s"'
                % (resource_id, self.stack_name)
            )
        return resource

    def copy(self):
        return Stack(metadata=dict(self.metadata), template=dict(self.template))


# FIXME: remove inheritance
class StackChangeSet(Stack):
    def __init__(self, stack: Stack, params=None, template=None):
        if template is None:
            template = {}
        if params is None:
            params = {}
        super(StackChangeSet, self).__init__(params, template)

        name = self.metadata["ChangeSetName"]
        if not self.metadata.get("ChangeSetId"):
            self.metadata["ChangeSetId"] = arns.cf_change_set_arn(name, change_set_id=short_uid())

        self.stack = stack
        self.metadata["StackId"] = stack.stack_id
        self.metadata["Status"] = "CREATE_PENDING"

    @property
    def change_set_id(self):
        return self.metadata["ChangeSetId"]

    @property
    def change_set_name(self):
        return self.metadata["ChangeSetName"]

    @property
    def resources(self):
        return dict(self.stack.resources)

    @property
    def changes(self):
        result = self.metadata["Changes"] = self.metadata.get("Changes", [])
        return result
