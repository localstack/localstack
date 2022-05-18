import json
import logging
from typing import Any, Dict, List, Optional

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudformation import (
    CallAs,
    ChangeSetNameOrId,
    ClientRequestToken,
    CloudformationApi,
    CreateChangeSetInput,
    CreateChangeSetOutput,
    CreateStackInput,
    CreateStackInstancesInput,
    CreateStackInstancesOutput,
    CreateStackOutput,
    CreateStackSetInput,
    CreateStackSetOutput,
    DeleteChangeSetOutput,
    DeleteStackSetOutput,
    DescribeChangeSetOutput,
    DescribeStackEventsOutput,
    DescribeStackResourceOutput,
    DescribeStackResourcesOutput,
    DescribeStackSetOperationOutput,
    DescribeStackSetOutput,
    DescribeStacksOutput,
    DisableRollback,
    ExecuteChangeSetOutput,
    ExecutionStatus,
    ExportName,
    GetTemplateOutput,
    GetTemplateSummaryInput,
    GetTemplateSummaryOutput,
    InvalidChangeSetStatusException,
    ListChangeSetsOutput,
    ListExportsOutput,
    ListImportsOutput,
    ListStackInstancesInput,
    ListStackInstancesOutput,
    ListStackResourcesOutput,
    ListStackSetsInput,
    ListStackSetsOutput,
    ListStacksOutput,
    LogicalResourceId,
    NextToken,
    PhysicalResourceId,
    RetainResources,
    RoleARN,
    StackName,
    StackNameOrId,
    StackSetName,
    StackStatusFilter,
    TemplateParameter,
    TemplateStage,
    UpdateStackInput,
    UpdateStackOutput,
    UpdateStackSetInput,
    UpdateStackSetOutput,
    ValidateTemplateInput,
    ValidateTemplateOutput,
)
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws import aws_stack
from localstack.utils.cloudformation import template_deployer, template_preparer
from localstack.utils.cloudformation.template_deployer import NoStackUpdates
from localstack.utils.cloudformation.template_preparer import (
    get_template_body,
    prepare_template_body,
    template_to_json,
)
from localstack.utils.collections import select_attributes
from localstack.utils.json import clone, clone_safe
from localstack.utils.objects import recurse_object
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.time import timestamp_millis

LOG = logging.getLogger(__name__)


class StackSet:
    """A stack set contains multiple stack instances."""

    def __init__(self, metadata=None):
        if metadata is None:
            metadata = {}
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

    def __init__(self, metadata=None):
        if metadata is None:
            metadata = {}
        self.metadata = metadata
        # reference to the deployed stack belonging to this stack instance
        self.stack = None


class Stack:
    def __init__(self, metadata=None, template=None):
        if template is None:
            template = {}
        self.metadata = metadata or {}
        self.template = template or {}
        self._template_raw = clone_safe(self.template)
        self.template_original = clone_safe(self.template)
        # initialize resources
        for resource_id, resource in self.template_resources.items():
            resource["LogicalResourceId"] = self.template_original["Resources"][resource_id][
                "LogicalResourceId"
            ] = (resource.get("LogicalResourceId") or resource_id)
        # initialize stack template attributes
        stack_id = self.metadata.get("StackId") or aws_stack.cloudformation_stack_arn(
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
        ]
        result = select_attributes(self.metadata, attrs)
        result["Tags"] = self.tags
        result["Outputs"] = self.outputs_list()
        result["Parameters"] = self.stack_parameters()
        for attr in ["Capabilities", "Outputs", "Parameters", "Tags"]:
            result.setdefault(attr, [])
        return result

    def set_stack_status(self, status):
        self.metadata["StackStatus"] = status
        self.metadata["StackStatusReason"] = "Deployment %s" % (
            "failed" if "FAILED" in status else "succeeded"
        )
        self.add_stack_event(self.stack_name, self.stack_id, status)

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
        if resource is None:
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

    def outputs_list(self) -> List[Dict]:
        """Returns a copy of the outputs of this stack."""
        result = []
        for k, details in self.outputs.items():
            value = None
            try:
                template_deployer.resolve_refs_recursively(self, details)
                value = details["Value"]
            except Exception as e:
                LOG.debug("Unable to resolve references in stack outputs: %s - %s", details, e)
            exports = details.get("Export") or {}
            export = exports.get("Name")
            export = template_deployer.resolve_refs_recursively(self, export)
            description = details.get("Description")
            entry = {
                "OutputKey": k,
                "OutputValue": value,
                "Description": description,
                "ExportName": export,
            }
            result.append(entry)
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
    def exports_map(self):
        result = {}
        for export in CloudFormationRegion.get().exports:
            result[export["Name"]] = export
        return result

    @property
    def nested_stacks(self):
        """Return a list of nested stacks that have been deployed by this stack."""
        result = [
            r for r in self.template_resources.values() if r["Type"] == "AWS::CloudFormation::Stack"
        ]
        result = [find_stack(r["Properties"].get("StackName")) for r in result]
        result = [r for r in result if r]
        return result

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


class StackChangeSet(Stack):
    def __init__(self, params=None, template=None):
        if template is None:
            template = {}
        if params is None:
            params = {}
        super(StackChangeSet, self).__init__(params, template)

        name = self.metadata["ChangeSetName"]
        if not self.metadata.get("ChangeSetId"):
            self.metadata["ChangeSetId"] = aws_stack.cf_change_set_arn(
                name, change_set_id=short_uid()
            )

        stack = self.stack = find_stack(self.metadata["StackName"])
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


class CloudFormationRegion(RegionBackend):
    def __init__(self):
        # maps stack ID to stack details
        self.stacks: Dict[str, Stack] = {}
        # maps stack set ID to stack set details
        self.stack_sets: Dict[str, StackSet] = {}

    @property
    def exports(self):
        exports = []
        output_keys = {}
        for stack_id, stack in self.stacks.items():
            for output in stack.outputs_list():
                export_name = output.get("ExportName")
                if not export_name:
                    continue
                if export_name in output_keys:
                    # TODO: raise exception on stack creation in case of duplicate exports
                    LOG.warning(
                        "Found duplicate export name %s in stacks: %s %s",
                        export_name,
                        output_keys[export_name],
                        stack.stack_id,
                    )
                entry = {
                    "ExportingStackId": stack.stack_id,
                    "Name": export_name,
                    "Value": output["OutputValue"],
                }
                exports.append(entry)
                output_keys[export_name] = stack.stack_id
        return exports


def clone_stack_params(stack_params):
    try:
        return clone(stack_params)
    except Exception as e:
        LOG.info("Unable to clone stack parameters: %s", e)
        return stack_params


def find_stack(stack_name: str) -> Optional[Stack]:
    state = CloudFormationRegion.get()
    return (
        [s for s in state.stacks.values() if stack_name in [s.stack_name, s.stack_id]] or [None]
    )[0]


def find_change_set(cs_name: str, stack_name: Optional[str] = None) -> Optional[StackChangeSet]:
    state = CloudFormationRegion.get()
    stack = find_stack(stack_name)
    stacks = [stack] if stack else state.stacks.values()
    result = [
        cs
        for s in stacks
        for cs in s.change_sets
        if cs_name in [cs.change_set_id, cs.change_set_name]
    ]
    return (result or [None])[0]


def stack_not_found_error(stack_name: str):
    # FIXME
    raise ValidationError("Stack with id %s does not exist" % stack_name)


def not_found_error(message: str):
    # FIXME
    raise ResourceNotFoundException(message)


class ValidationError(CommonServiceException):
    """General validation error type (defined in the AWS docs, but not part of the botocore spec)"""

    def __init__(self, message=None):
        super().__init__("ValidationError", message=message, sender_fault=True)


class ResourceNotFoundException(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("ResourceNotFoundException", status_code=404, message=message)


class InternalFailure(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InternalFailure", status_code=500, message=message, sender_fault=False)


class CloudformationProvider(CloudformationApi):
    @handler("CreateStack", expand=False)
    def create_stack(self, context: RequestContext, request: CreateStackInput) -> CreateStackOutput:
        state = CloudFormationRegion.get()
        template_deployer.prepare_template_body(request)  # TODO: avoid mutating request directly
        template = template_preparer.parse_template(request["TemplateBody"])
        stack_name = template["StackName"] = request.get("StackName")
        stack = Stack(request, template)

        # find existing stack with same name, and remove it if this stack is in DELETED state
        existing = ([s for s in state.stacks.values() if s.stack_name == stack_name] or [None])[0]
        if existing:
            if "DELETE" not in existing.status:
                raise ValidationError(
                    f'Stack named "{stack_name}" already exists with status "{existing.status}"'
                )
            state.stacks.pop(existing.stack_id)

        state.stacks[stack.stack_id] = stack
        LOG.debug(
            'Creating stack "%s" with %s resources ...',
            stack.stack_name,
            len(stack.template_resources),
        )
        deployer = template_deployer.TemplateDeployer(stack)
        try:
            # TODO: create separate step to first resolve parameters
            deployer.deploy_stack()
        except Exception as e:
            stack.set_stack_status("CREATE_FAILED")
            msg = 'Unable to create stack "%s": %s' % (stack.stack_name, e)
            LOG.exception("%s")
            raise ValidationError(msg) from e

        return CreateStackOutput(StackId=stack.stack_id)

    @handler("DeleteStack")
    def delete_stack(
        self,
        context: RequestContext,
        stack_name: StackName,
        retain_resources: RetainResources = None,
        role_arn: RoleARN = None,
        client_request_token: ClientRequestToken = None,
    ) -> None:
        stack = find_stack(stack_name)
        deployer = template_deployer.TemplateDeployer(stack)
        deployer.delete_stack()

    @handler("UpdateStack", expand=False)
    def update_stack(
        self,
        context: RequestContext,
        request: UpdateStackInput,
    ) -> UpdateStackOutput:
        stack_name = request.get("StackName")
        stack = find_stack(stack_name)
        if not stack:
            return not_found_error(f'Unable to update non-existing stack "{stack_name}"')

        template_preparer.prepare_template_body(request)
        template = template_preparer.parse_template(request["TemplateBody"])
        new_stack = Stack(request, template)
        deployer = template_deployer.TemplateDeployer(stack)
        try:
            deployer.update_stack(new_stack)
        except Exception as e:
            stack.set_stack_status("UPDATE_FAILED")
            msg = f'Unable to update stack "{stack_name}": {e}'
            LOG.exception("%s", msg)
            raise ValidationError(msg) from e

        return UpdateStackOutput(StackId=stack.stack_id)

    @handler("DescribeStacks")
    def describe_stacks(
        self, context: RequestContext, stack_name: StackName = None, next_token: NextToken = None
    ) -> DescribeStacksOutput:
        state = CloudFormationRegion.get()
        stack_list = list(state.stacks.values())
        stacks = [
            s.describe_details()
            for s in stack_list
            if stack_name in [None, s.stack_name, s.stack_id]
        ]

        if stack_name and not stacks:
            raise ValidationError(f"Stack with id {stack_name} does not exist")

        return DescribeStacksOutput(Stacks=stacks)

    @handler("ListStacks")
    def list_stacks(
        self,
        context: RequestContext,
        next_token: NextToken = None,
        stack_status_filter: StackStatusFilter = None,
    ) -> ListStacksOutput:
        state = CloudFormationRegion.get()

        stacks = [
            s.describe_details()
            for s in state.stacks.values()
            if not stack_status_filter or s.status in stack_status_filter
        ]

        attrs = [
            "StackId",
            "StackName",
            "TemplateDescription",
            "CreationTime",
            "LastUpdatedTime",
            "DeletionTime",
            "StackStatus",
            "StackStatusReason",
            "ParentId",
            "RootId",
            "DriftInformation",
        ]
        stacks = [select_attributes(stack, attrs) for stack in stacks]
        return ListStacksOutput(StackSummaries=stacks)

    @handler("GetTemplate")
    def get_template(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        change_set_name: ChangeSetNameOrId = None,
        template_stage: TemplateStage = None,
    ) -> GetTemplateOutput:

        stack = find_stack(stack_name)
        if change_set_name:
            stack = find_change_set(stack_name=stack_name, cs_name=change_set_name)
        if not stack:
            return stack_not_found_error(stack_name)
        return GetTemplateOutput(TemplateBody=json.dumps(stack.latest_template_raw()))

    @handler("GetTemplateSummary", expand=False)
    def get_template_summary(
        self,
        context: RequestContext,
        request: GetTemplateSummaryInput,
    ) -> GetTemplateSummaryOutput:
        stack_name = request.get("StackName")

        if stack_name:
            stack = find_stack(stack_name)
            if not stack:
                return stack_not_found_error(stack_name)
        else:
            template_deployer.prepare_template_body(request)
            template = template_preparer.parse_template(request["TemplateBody"])
            request["StackName"] = "tmp-stack"
            stack = Stack(request, template)

        result: GetTemplateSummaryOutput = stack.describe_details()
        id_summaries = {}
        for resource_id, resource in stack.template_resources.items():
            res_type = resource["Type"]
            id_summaries[res_type] = id_summaries.get(res_type) or []
            id_summaries[res_type].append(resource_id)

        result["ResourceTypes"] = list(id_summaries.keys())
        result["ResourceIdentifierSummaries"] = [
            {"ResourceType": key, "LogicalResourceIds": values}
            for key, values in id_summaries.items()
        ]
        return result

    @handler("ValidateTemplate", expand=False)
    def validate_template(
        self, context: RequestContext, request: ValidateTemplateInput
    ) -> ValidateTemplateOutput:
        try:
            # TODO implement actual validation logic
            template_body = get_template_body(request)
            valid_template = json.loads(template_to_json(template_body))

            parameters = [
                TemplateParameter(
                    ParameterKey=k,
                    DefaultValue=v.get("Default", ""),
                    NoEcho=False,
                    Description=v.get("Description", ""),
                )
                for k, v in valid_template.get("Parameters", {}).items()
            ]

            return ValidateTemplateOutput(
                Description=valid_template.get("Description"), Parameters=parameters
            )
        except Exception as e:
            LOG.exception("Error validating template")
            raise ValidationError("Template Validation Error") from e

    @handler("CreateStackSet", expand=False)
    def create_stack_set(
        self, context: RequestContext, request: CreateStackSetInput
    ) -> CreateStackSetOutput:
        state = CloudFormationRegion.get()
        stack_set = StackSet(request)
        stack_set_id = short_uid()
        stack_set.metadata["StackSetId"] = stack_set_id
        state.stack_sets[stack_set_id] = stack_set

        return CreateStackSetOutput(StackSetId=stack_set_id)

    @handler("DescribeStackSet")
    def describe_stack_set(
        self, context: RequestContext, stack_set_name: StackSetName, call_as: CallAs = None
    ) -> DescribeStackSetOutput:
        state = CloudFormationRegion.get()
        result = [
            sset.metadata
            for sset in state.stack_sets.values()
            if sset.stack_set_name == stack_set_name
        ]
        if not result:
            return not_found_error(f'Unable to find stack set "{stack_set_name}"')

        return DescribeStackSetOutput(StackSet=result[0])

    @handler("UpdateStackSet", expand=False)
    def update_stack_set(
        self, context: RequestContext, request: UpdateStackSetInput
    ) -> UpdateStackSetOutput:
        state = CloudFormationRegion.get()
        set_name = request.get("StackSetName")
        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')
        stack_set = stack_set[0]
        stack_set.metadata.update(request)
        op_id = request.get("OperationId") or short_uid()
        operation = {
            "OperationId": op_id,
            "StackSetId": stack_set.metadata["StackSetId"],
            "Action": "UPDATE",
            "Status": "SUCCEEDED",
        }
        stack_set.operations[op_id] = operation
        return UpdateStackSetOutput(OperationId=op_id)

    @handler("DeleteStackSet")
    def delete_stack_set(
        self, context: RequestContext, stack_set_name: StackSetName, call_as: CallAs = None
    ) -> DeleteStackSetOutput:
        state = CloudFormationRegion.get()
        stack_set = [
            sset for sset in state.stack_sets.values() if sset.stack_set_name == stack_set_name
        ]

        if not stack_set:
            return not_found_error(f'Stack set named "{stack_set_name}" does not exist')

        for instance in stack_set[0].stack_instances:
            deployer = template_deployer.TemplateDeployer(instance.stack)
            deployer.delete_stack()
        return DeleteStackSetOutput()

    @handler("ListStackSets", expand=False)
    def list_stack_sets(
        self, context: RequestContext, request: ListStackSetsInput
    ) -> ListStackSetsOutput:
        state = CloudFormationRegion.get()
        result = [sset.metadata for sset in state.stack_sets.values()]
        return ListStackSetsOutput(Summaries=result)

    @handler("CreateChangeSet", expand=False)
    def create_change_set(
        self, context: RequestContext, request: CreateChangeSetInput
    ) -> CreateChangeSetOutput:
        req_params = request
        change_set_type = req_params.get("ChangeSetType", "UPDATE")
        stack_name = req_params.get("StackName")
        change_set_name = req_params.get("ChangeSetName")
        template_body = req_params.get("TemplateBody")
        # s3 or secretsmanager url
        template_url = req_params.get("TemplateURL")

        stack = find_stack(stack_name)

        # validate and resolve template
        if template_body and template_url:
            raise ValidationError(
                "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
            )  # TODO: check proper message

        if not template_body and not template_url:
            raise ValidationError(
                "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
            )  # TODO: check proper message

        prepare_template_body(req_params)  # TODO: function has too many unclear responsibilities
        template = template_preparer.parse_template(req_params["TemplateBody"])
        del req_params["TemplateBody"]  # TODO: stop mutating req_params
        template["StackName"] = stack_name
        template[
            "ChangeSetName"
        ] = change_set_name  # TODO: validate with AWS what this is actually doing?

        if change_set_type == "UPDATE":
            # add changeset to existing stack
            if stack is None:
                raise ValidationError(
                    f"Stack '{stack_name}' does not exist."
                )  # stack should exist already
        elif change_set_type == "CREATE":
            # create new (empty) stack
            if stack is not None:
                raise ValidationError(
                    f"Stack {stack_name} already exists"
                )  # stack should not exist yet (TODO: check proper message)
            state = CloudFormationRegion.get()
            empty_stack_template = dict(template)
            empty_stack_template["Resources"] = {}
            req_params_copy = clone_stack_params(req_params)
            stack = Stack(req_params_copy, empty_stack_template)
            state.stacks[stack.stack_id] = stack
            stack.set_stack_status("REVIEW_IN_PROGRESS")
        elif change_set_type == "IMPORT":
            raise NotImplementedError()  # TODO: implement importing resources
        else:
            msg = (
                f"1 validation error detected: Value '{change_set_type}' at 'changeSetType' failed to satisfy "
                f"constraint: Member must satisfy enum value set: [IMPORT, UPDATE, CREATE] "
            )
            raise ValidationError(msg)

        change_set = StackChangeSet(req_params, template)
        # TODO: refactor the flow here
        deployer = template_deployer.TemplateDeployer(change_set)
        changes = deployer.construct_changes(
            stack,
            change_set,
            change_set_id=change_set.change_set_id,
            append_to_changeset=True,
            filter_unchanged_resources=True,
        )
        deployer.apply_parameter_changes(
            change_set, change_set
        )  # TODO: bandaid to populate metadata
        stack.change_sets.append(change_set)
        if not changes:
            change_set.metadata["Status"] = "FAILED"
            change_set.metadata["ExecutionStatus"] = "UNAVAILABLE"
            change_set.metadata[
                "StatusReason"
            ] = "The submitted information didn't contain changes. Submit different information to create a change set."
        else:
            change_set.metadata[
                "Status"
            ] = "CREATE_COMPLETE"  # technically for some time this should first be CREATE_PENDING
            change_set.metadata[
                "ExecutionStatus"
            ] = "AVAILABLE"  # technically for some time this should first be UNAVAILABLE

        return CreateChangeSetOutput(StackId=change_set.stack_id, Id=change_set.change_set_id)

    @handler("DescribeChangeSet")
    def describe_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        next_token: NextToken = None,
    ) -> DescribeChangeSetOutput:
        change_set = find_change_set(change_set_name, stack_name=stack_name)
        if not change_set:
            return not_found_error(
                f'Unable to find change set "{change_set_name}" for stack "{stack_name}"'
            )

        return change_set.metadata

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
    ) -> DeleteChangeSetOutput:
        change_set = find_change_set(change_set_name, stack_name=stack_name)
        if not change_set:
            return not_found_error(
                f'Unable to find change set "{change_set_name}" for stack "{stack_name}"'
            )
        change_set.stack.change_sets = [
            cs for cs in change_set.stack.change_sets if cs.change_set_name != change_set_name
        ]
        return DeleteChangeSetOutput()

    @handler("ExecuteChangeSet")
    def execute_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        client_request_token: ClientRequestToken = None,
        disable_rollback: DisableRollback = None,
    ) -> ExecuteChangeSetOutput:
        change_set = find_change_set(change_set_name, stack_name=stack_name)
        if not change_set:
            return not_found_error(
                f'Unable to find change set "{change_set_name}" for stack "{stack_name}"'
            )
        if change_set.metadata.get("ExecutionStatus") != ExecutionStatus.AVAILABLE:
            LOG.debug("Change set %s not in execution status 'AVAILABLE'", change_set_name)
            raise InvalidChangeSetStatusException(
                f"ChangeSet [{change_set.metadata['ChangeSetId']}] cannot be executed in its current status of [{change_set.metadata.get('Status')}]"
            )
        stack_name = change_set.stack.stack_name
        LOG.debug(
            'Executing change set "%s" for stack "%s" with %s resources ...',
            change_set_name,
            stack_name,
            len(change_set.template_resources),
        )
        deployer = template_deployer.TemplateDeployer(change_set.stack)
        try:
            deployer.apply_change_set(change_set)
            change_set.stack.metadata["ChangeSetId"] = change_set.change_set_id
        except NoStackUpdates:
            # TODO: parity-check if this exception should be re-raised or swallowed
            raise ValidationError("No updates to be performed for stack change set")

        return ExecuteChangeSetOutput()

    @handler("ListChangeSets")
    def list_change_sets(
        self, context: RequestContext, stack_name: StackNameOrId, next_token: NextToken = None
    ) -> ListChangeSetsOutput:
        stack = find_stack(stack_name)
        if not stack:
            return not_found_error(f'Unable to find stack "{stack_name}"')
        result = [cs.metadata for cs in stack.change_sets]
        return ListChangeSetsOutput(Summaries=result)

    @handler("CreateStackInstances", expand=False)
    def create_stack_instances(
        self,
        context: RequestContext,
        request: CreateStackInstancesInput,
    ) -> CreateStackInstancesOutput:
        state = CloudFormationRegion.get()

        set_name = request.get("StackSetName")
        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]

        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')

        stack_set = stack_set[0]
        op_id = request.get("OperationId") or short_uid()
        sset_meta = stack_set.metadata
        accounts = request["Accounts"]
        regions = request["Regions"]

        stacks_to_await = []
        for account in accounts:
            for region in regions:
                # deploy new stack
                LOG.debug('Deploying instance for stack set "%s" in region "%s"', set_name, region)
                cf_client = aws_stack.connect_to_service("cloudformation", region_name=region)
                kwargs = select_attributes(sset_meta, ["TemplateBody"]) or select_attributes(
                    sset_meta, ["TemplateURL"]
                )
                stack_name = f"sset-{set_name}-{account}"
                result = cf_client.create_stack(StackName=stack_name, **kwargs)
                stacks_to_await.append((stack_name, region))
                # store stack instance
                instance = {
                    "StackSetId": sset_meta["StackSetId"],
                    "OperationId": op_id,
                    "Account": account,
                    "Region": region,
                    "StackId": result["StackId"],
                    "Status": "CURRENT",
                    "StackInstanceStatus": {"DetailedStatus": "SUCCEEDED"},
                }
                instance = StackInstance(instance)
                stack_set.stack_instances.append(instance)

        # wait for completion of stack
        for stack in stacks_to_await:
            aws_stack.await_stack_completion(stack[0], region_name=stack[1])

        # record operation
        operation = {
            "OperationId": op_id,
            "StackSetId": stack_set.metadata["StackSetId"],
            "Action": "CREATE",
            "Status": "SUCCEEDED",
        }
        stack_set.operations[op_id] = operation

        return CreateStackInstancesOutput(OperationId=op_id)

    @handler("ListStackInstances", expand=False)
    def list_stack_instances(
        self,
        context: RequestContext,
        request: ListStackInstancesInput,
    ) -> ListStackInstancesOutput:
        set_name = request.get("StackSetName")
        state = CloudFormationRegion.get()
        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')

        stack_set = stack_set[0]
        result = [inst.metadata for inst in stack_set.stack_instances]
        return ListStackInstancesOutput(Summaries=result)

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken = None
    ) -> ListExportsOutput:
        state = CloudFormationRegion.get()
        return ListExportsOutput(Exports=state.exports)

    @handler("ListImports")
    def list_imports(
        self, context: RequestContext, export_name: ExportName, next_token: NextToken = None
    ) -> ListImportsOutput:
        state = CloudFormationRegion.get()

        importing_stack_names = []
        for stack in state.stacks.values():
            if export_name in stack.imports:
                importing_stack_names.append(stack.stack_name)

        return ListImportsOutput(Imports=importing_stack_names)

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self, context: RequestContext, stack_name: StackName = None, next_token: NextToken = None
    ) -> DescribeStackEventsOutput:
        state = CloudFormationRegion.get()

        events = []
        for stack_id, stack in state.stacks.items():
            if stack_name in [None, stack.stack_name, stack.stack_id]:
                events.extend(stack.events)

        return DescribeStackEventsOutput(StackEvents=events)

    @handler("DescribeStackResource")
    def describe_stack_resource(
        self, context: RequestContext, stack_name: StackName, logical_resource_id: LogicalResourceId
    ) -> DescribeStackResourceOutput:
        stack = find_stack(stack_name)

        if not stack:
            return stack_not_found_error(stack_name)

        details = stack.resource_status(logical_resource_id)
        return DescribeStackResourceOutput(StackResourceDetail=details)

    @handler("DescribeStackResources")
    def describe_stack_resources(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        logical_resource_id: LogicalResourceId = None,
        physical_resource_id: PhysicalResourceId = None,
    ) -> DescribeStackResourcesOutput:

        if physical_resource_id and stack_name:
            raise ValidationError("Cannot specify both StackName and PhysicalResourceId")
        # TODO: filter stack by PhysicalResourceId!
        stack = find_stack(stack_name)
        if not stack:
            return stack_not_found_error(stack_name)
        statuses = [
            res_status
            for res_id, res_status in stack.resource_states.items()
            if logical_resource_id in [res_id, None]
        ]
        return DescribeStackResourcesOutput(StackResources=statuses)

    @handler("ListStackResources")
    def list_stack_resources(
        self, context: RequestContext, stack_name: StackName, next_token: NextToken = None
    ) -> ListStackResourcesOutput:
        result = self.describe_stack_resources(context, stack_name)
        return ListStackResourcesOutput(StackResourceSummaries=result.pop("StackResources"))

    @handler("DescribeStackSetOperation")
    def describe_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs = None,
    ) -> DescribeStackSetOperationOutput:
        state = CloudFormationRegion.get()

        set_name = stack_set_name

        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
        if not stack_set:
            return not_found_error(f'Unable to find stack set "{set_name}"')
        stack_set = stack_set[0]
        result = stack_set.operations.get(operation_id)
        if not result:
            LOG.debug(
                'Unable to find operation ID "%s" for stack set "%s" in list: %s',
                operation_id,
                set_name,
                list(stack_set.operations.keys()),
            )
            return not_found_error(
                f'Unable to find operation ID "{operation_id}" for stack set "{set_name}"'
            )

        return DescribeStackSetOperationOutput(StackSetOperation=result)
