import json
import logging
import re
from collections import defaultdict
from copy import deepcopy

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudformation import (
    CallAs,
    ChangeSetNameOrId,
    ChangeSetNotFoundException,
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
from localstack.services.cloudformation import api_utils
from localstack.services.cloudformation.engine import template_deployer, template_preparer
from localstack.services.cloudformation.engine.entities import (
    Stack,
    StackChangeSet,
    StackInstance,
    StackSet,
)
from localstack.services.cloudformation.engine.template_deployer import NoStackUpdates
from localstack.services.cloudformation.stores import (
    find_change_set,
    find_stack,
    get_cloudformation_store,
)
from localstack.utils.aws import aws_stack
from localstack.utils.collections import remove_attributes, select_attributes
from localstack.utils.json import clone
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)

ARN_CHANGESET_REGEX = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):cloudformation:[-a-zA-Z0-9]+:\d{12}:changeSet/[a-zA-Z][-a-zA-Z0-9]*/[-a-zA-Z0-9:/._+]+"
)
ARN_STACK_REGEX = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):cloudformation:[-a-zA-Z0-9]+:\d{12}:stack/[a-zA-Z][-a-zA-Z0-9]*/[-a-zA-Z0-9:/._+]+"
)


def clone_stack_params(stack_params):
    try:
        return clone(stack_params)
    except Exception as e:
        LOG.info("Unable to clone stack parameters: %s", e)
        return stack_params


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

        # TODO: test what happens when both TemplateUrl and Body are specified
        state = get_cloudformation_store()
        api_utils.prepare_template_body(request)  # TODO: avoid mutating request directly
        template = template_preparer.parse_template(request["TemplateBody"])
        stack_name = template["StackName"] = request.get("StackName")
        stack = Stack(request, template)  # TODO: proper body handling like in create_change_set

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

        api_utils.prepare_template_body(request)
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
        state = get_cloudformation_store()
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
        state = get_cloudformation_store()

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

        stack = None
        if change_set_name:
            stack = find_change_set(stack_name=stack_name, cs_name=change_set_name)
        else:
            stack = find_stack(stack_name)
        if not stack:
            return stack_not_found_error(stack_name)

        return GetTemplateOutput(
            TemplateBody=stack.template_body,
            StagesAvailable=[TemplateStage.Original, TemplateStage.Processed],
        )

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
            api_utils.prepare_template_body(request)
            template = template_preparer.parse_template(request["TemplateBody"])
            request["StackName"] = "tmp-stack"
            stack = Stack(request, template)

        result: GetTemplateSummaryOutput = stack.describe_details()
        result["Parameters"] = result.get("Parameters") or []
        id_summaries = defaultdict(list)
        for resource_id, resource in stack.template_resources.items():
            res_type = resource["Type"]
            id_summaries[res_type].append(resource_id)

        result["ResourceTypes"] = list(id_summaries.keys())
        result["ResourceIdentifierSummaries"] = [
            {"ResourceType": key, "LogicalResourceIds": values}
            for key, values in id_summaries.items()
        ]
        result["Version"] = stack.template.get("AWSTemplateFormatVersion", "2010-09-09")
        # these do not appear in the output
        result.pop("Capabilities", None)
        return result

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

        api_utils.prepare_template_body(
            req_params
        )  # TODO: function has too many unclear responsibilities
        if not template_body:
            template_body = req_params[
                "TemplateBody"
            ]  # should then have been set by prepare_template_body
        template = template_preparer.parse_template(req_params["TemplateBody"])
        del req_params["TemplateBody"]  # TODO: stop mutating req_params
        template["StackName"] = stack_name
        # TODO: validate with AWS what this is actually doing?
        template["ChangeSetName"] = change_set_name

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
            state = get_cloudformation_store()
            empty_stack_template = dict(template)
            empty_stack_template["Resources"] = {}
            req_params_copy = clone_stack_params(req_params)
            stack = Stack(
                req_params_copy,
                empty_stack_template,
                template_body=template_body,
            )
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

        change_set = StackChangeSet(stack, req_params, template)
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

        # only relevant if change_set_name isn't an ARN
        if not ARN_CHANGESET_REGEX.match(change_set_name):
            if not stack_name:
                raise ValidationError(
                    "StackName must be specified if ChangeSetName is not specified as an ARN."
                )

            stack = find_stack(stack_name)
            if not stack:
                raise ValidationError(f"Stack [{stack_name}] does not exist")

        change_set = find_change_set(change_set_name, stack_name=stack_name)
        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")

        attrs = [
            "ChangeSetType",
            "StackStatus",
            "LastUpdatedTime",
            "DisableRollback",
            "EnableTerminationProtection",
        ]
        result = remove_attributes(deepcopy(change_set.metadata), attrs)
        return result

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
    ) -> DeleteChangeSetOutput:

        # only relevant if change_set_name isn't an ARN
        if not ARN_CHANGESET_REGEX.match(change_set_name):
            if not stack_name:
                raise ValidationError(
                    "StackName must be specified if ChangeSetName is not specified as an ARN."
                )

            stack = find_stack(stack_name)
            if not stack:
                raise ValidationError(f"Stack [{stack_name}] does not exist")

        change_set = find_change_set(change_set_name, stack_name=stack_name)
        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")
        change_set.stack.change_sets = [
            cs
            for cs in change_set.stack.change_sets
            if change_set_name not in (cs.change_set_name, cs.change_set_id)
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
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")
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

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken = None
    ) -> ListExportsOutput:
        state = get_cloudformation_store()
        return ListExportsOutput(Exports=state.exports)

    @handler("ListImports")
    def list_imports(
        self, context: RequestContext, export_name: ExportName, next_token: NextToken = None
    ) -> ListImportsOutput:
        state = get_cloudformation_store()

        importing_stack_names = []
        for stack in state.stacks.values():
            if export_name in stack.imports:
                importing_stack_names.append(stack.stack_name)

        return ListImportsOutput(Imports=importing_stack_names)

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self, context: RequestContext, stack_name: StackName = None, next_token: NextToken = None
    ) -> DescribeStackEventsOutput:
        state = get_cloudformation_store()

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
        for status in statuses:
            status.setdefault("DriftInformation", {"StackResourceDriftStatus": "NOT_CHECKED"})
        return DescribeStackResourcesOutput(StackResources=statuses)

    @handler("ListStackResources")
    def list_stack_resources(
        self, context: RequestContext, stack_name: StackName, next_token: NextToken = None
    ) -> ListStackResourcesOutput:
        result = self.describe_stack_resources(context, stack_name)

        resources = deepcopy(result.get("StackResources", []))
        for resource in resources:
            attrs = ["StackName", "StackId", "Timestamp", "PreviousResourceStatus"]
            remove_attributes(resource, attrs)

        return ListStackResourcesOutput(StackResourceSummaries=resources)

    @handler("ValidateTemplate", expand=False)
    def validate_template(
        self, context: RequestContext, request: ValidateTemplateInput
    ) -> ValidateTemplateOutput:
        try:
            # TODO implement actual validation logic
            template_body = api_utils.get_template_body(request)
            valid_template = json.loads(template_preparer.template_to_json(template_body))

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

    # =======================================
    # =============  Stack Set  =============
    # =======================================

    @handler("CreateStackSet", expand=False)
    def create_stack_set(
        self, context: RequestContext, request: CreateStackSetInput
    ) -> CreateStackSetOutput:
        state = get_cloudformation_store()
        stack_set = StackSet(request)
        stack_set_id = short_uid()
        stack_set.metadata["StackSetId"] = stack_set_id
        state.stack_sets[stack_set_id] = stack_set

        return CreateStackSetOutput(StackSetId=stack_set_id)

    @handler("DescribeStackSetOperation")
    def describe_stack_set_operation(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        operation_id: ClientRequestToken,
        call_as: CallAs = None,
    ) -> DescribeStackSetOperationOutput:
        state = get_cloudformation_store()

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

    @handler("DescribeStackSet")
    def describe_stack_set(
        self, context: RequestContext, stack_set_name: StackSetName, call_as: CallAs = None
    ) -> DescribeStackSetOutput:
        state = get_cloudformation_store()
        result = [
            sset.metadata
            for sset in state.stack_sets.values()
            if sset.stack_set_name == stack_set_name
        ]
        if not result:
            return not_found_error(f'Unable to find stack set "{stack_set_name}"')

        return DescribeStackSetOutput(StackSet=result[0])

    @handler("ListStackSets", expand=False)
    def list_stack_sets(
        self, context: RequestContext, request: ListStackSetsInput
    ) -> ListStackSetsOutput:
        state = get_cloudformation_store()
        result = [sset.metadata for sset in state.stack_sets.values()]
        return ListStackSetsOutput(Summaries=result)

    @handler("UpdateStackSet", expand=False)
    def update_stack_set(
        self, context: RequestContext, request: UpdateStackSetInput
    ) -> UpdateStackSetOutput:
        state = get_cloudformation_store()
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
        state = get_cloudformation_store()
        stack_set = [
            sset for sset in state.stack_sets.values() if sset.stack_set_name == stack_set_name
        ]

        if not stack_set:
            return not_found_error(f'Stack set named "{stack_set_name}" does not exist')

        for instance in stack_set[0].stack_instances:
            deployer = template_deployer.TemplateDeployer(instance.stack)
            deployer.delete_stack()
        return DeleteStackSetOutput()

    @handler("CreateStackInstances", expand=False)
    def create_stack_instances(
        self,
        context: RequestContext,
        request: CreateStackInstancesInput,
    ) -> CreateStackInstancesOutput:
        state = get_cloudformation_store()

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
            client = aws_stack.connect_to_service("cloudformation", region_name=stack[1])
            client.get_waiter("stack_create_complete").wait(StackName=stack[0])

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
        state = get_cloudformation_store()
        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')

        stack_set = stack_set[0]
        result = [inst.metadata for inst in stack_set.stack_instances]
        return ListStackInstancesOutput(Summaries=result)
