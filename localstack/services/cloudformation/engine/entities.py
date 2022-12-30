import logging
from typing import Any, Dict, List, Optional, TypedDict

from localstack.aws.api.cloudformation import Capability, ChangeSetType, Parameter
from localstack.utils.aws import arns, aws_stack
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
        params = self.stack_parameters()
        if params:
            result["Parameters"] = params
        if not result.get("DriftInformation"):
            result["DriftInformation"] = {"StackDriftStatus": "NOT_CHECKED"}
        for attr in ["Capabilities", "Tags", "NotificationARNs"]:
            result.setdefault(attr, [])
        return result

    def set_stack_status(self, status):
        self.metadata["StackStatus"] = status
        if "FAILED" in status:
            self.metadata["StackStatusReason"] = "Deployment failed"
        self.add_stack_event(self.stack_name, self.stack_id, status)

    def set_time_attribute(self, attribute, new_time=None):
        self.metadata[attribute] = new_time or timestamp_millis()

    def add_stack_event(self, resource_id: str, physical_res_id: str, status: str):
        event = {
            "EventId": long_uid(),
            "Timestamp": timestamp_millis(),
            "StackId": self.stack_id,
            "StackName": self.stack_name,
            "LogicalResourceId": resource_id,
            "PhysicalResourceId": physical_res_id,
            "ResourceStatus": status,
            "ResourceType": "AWS::CloudFormation::Stack",
        }
        self.events.insert(0, event)

    def set_resource_status(self, resource_id: str, status: str, physical_res_id: str = None):
        """Update the deployment status of the given resource ID and publish a corresponding stack event."""
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

    # TODO: potential performance issues due to many stack_parameters calls (cache or limit actual invocations)
    @property
    def resources(self):  # TODO: not actually resources, split apart
        """Return dict of resources, parameters, conditions, and other stack metadata."""
        result = dict(self.template_resources)

        # add stack params (without defaults)
        stack_params = self._resolve_stack_parameters(defaults=False, existing=result)
        result.update(stack_params)

        # TODO: conditions and mappings don't really belong here and should be handled separately
        for name, value in self.conditions.items():
            if name not in result:
                result[name] = {
                    "Type": "Parameter",
                    "LogicalResourceId": name,
                    "Properties": {"Value": value},
                }
        for name, value in self.mappings.items():
            if name not in result:
                result[name] = {
                    "Type": "Parameter",
                    "LogicalResourceId": name,
                    "Properties": {"Value": value},
                }

        stack_params = self._resolve_stack_parameters(defaults=True, existing=result)
        result.update(stack_params)

        return result

    def _resolve_stack_parameters(
        self, defaults=True, existing: Dict[str, Dict] = None
    ) -> Dict[str, Dict]:
        """Resolve the parameter values of this stack, skipping the params already present in `existing`"""
        existing = existing or {}
        result = {}
        for param in self.stack_parameters(defaults=defaults):
            param_key = param["ParameterKey"]
            if param_key not in existing:
                resolved_value = param.get("ResolvedValue")
                prop_value = (
                    resolved_value if resolved_value is not None else param.get("ParameterValue")
                )
                result[param["ParameterKey"]] = {
                    "Type": "Parameter",
                    "LogicalResourceId": param_key,
                    "Properties": {"Value": prop_value},
                }
        return result

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

    # TODO: check if metadata already populated/resolved and use it if possible (avoid unnecessary re-resolving)
    def stack_parameters(self, defaults=True) -> List[Dict[str, Any]]:
        result = {}
        # add default template parameter values
        if defaults:
            for key, value in self.template_parameters.items():
                param_value = value.get("Default")
                result[key] = {
                    "ParameterKey": key,
                    "ParameterValue": param_value,
                }
                # TODO: extract dynamic parameter resolving
                # TODO: support different types and refactor logic to use metadata (here not yet populated properly)
                param_type = value.get("Type", "")
                if not param_type:
                    if param_type == "AWS::SSM::Parameter::Value<String>":
                        ssm_client = aws_stack.connect_to_service("ssm")
                        resolved_value = ssm_client.get_parameter(Name=param_value)["Parameter"][
                            "Value"
                        ]
                        result[key]["ResolvedValue"] = resolved_value
                    elif param_type.startswith("AWS::"):
                        LOG.info(
                            f"Parameter Type '{param_type}' is currently not supported. Coming soon, stay tuned!"
                        )
                    else:
                        # lets assume we support the normal CFn parameters
                        pass

        # add stack parameters
        result.update({p["ParameterKey"]: p for p in self.metadata["Parameters"]})
        # add parameters of change sets
        for change_set in self.change_sets:
            for param in change_set.metadata["Parameters"]:
                if not param.get("UsePreviousValue"):
                    result.update({param["ParameterKey"]: param})
        result = list(result.values())
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

    def stack_parameters(self, defaults=True) -> List[Dict[str, Any]]:
        return self.stack.stack_parameters(defaults=defaults)
