import copy
import json
import logging
import re
from collections import defaultdict
from copy import deepcopy

from localstack.aws.api import CommonServiceException, RequestContext, handler
from localstack.aws.api.cloudformation import (
    AlreadyExistsException,
    CallAs,
    ChangeSetNameOrId,
    ChangeSetNotFoundException,
    ChangeSetType,
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
    DeleteStackInstancesInput,
    DeleteStackInstancesOutput,
    DeleteStackSetOutput,
    DeletionMode,
    DescribeChangeSetOutput,
    DescribeStackEventsOutput,
    DescribeStackResourceOutput,
    DescribeStackResourcesOutput,
    DescribeStackSetOperationOutput,
    DescribeStackSetOutput,
    DescribeStacksOutput,
    DisableRollback,
    EnableTerminationProtection,
    ExecuteChangeSetOutput,
    ExecutionStatus,
    ExportName,
    GetTemplateOutput,
    GetTemplateSummaryInput,
    GetTemplateSummaryOutput,
    IncludePropertyValues,
    InsufficientCapabilitiesException,
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
    Parameter,
    PhysicalResourceId,
    RegisterTypeInput,
    RegisterTypeOutput,
    RetainExceptOnCreate,
    RetainResources,
    RoleARN,
    StackName,
    StackNameOrId,
    StackSetName,
    StackStatus,
    StackStatusFilter,
    TemplateParameter,
    TemplateStage,
    UpdateStackInput,
    UpdateStackOutput,
    UpdateStackSetInput,
    UpdateStackSetOutput,
    UpdateTerminationProtectionOutput,
    ValidateTemplateInput,
    ValidateTemplateOutput,
)
from localstack.aws.connect import connect_to
from localstack.services.cloudformation import api_utils
from localstack.services.cloudformation.engine import parameters as param_resolver
from localstack.services.cloudformation.engine import template_deployer, template_preparer
from localstack.services.cloudformation.engine.entities import (
    Stack,
    StackChangeSet,
    StackInstance,
    StackSet,
)
from localstack.services.cloudformation.engine.parameters import strip_parameter_type
from localstack.services.cloudformation.engine.resource_ordering import (
    NoResourceInStack,
    order_resources,
)
from localstack.services.cloudformation.engine.template_deployer import (
    NoStackUpdates,
)
from localstack.services.cloudformation.engine.template_utils import resolve_stack_conditions
from localstack.services.cloudformation.engine.transformers import (
    FailedTransformationException,
)
from localstack.services.cloudformation.engine.validations import (
    DEFAULT_TEMPLATE_VALIDATIONS,
    ValidationError,
)
from localstack.services.cloudformation.stores import (
    cloudformation_stores,
    find_active_stack_by_name_or_id,
    find_change_set,
    find_stack,
    find_stack_by_id,
    get_cloudformation_store,
)
from localstack.state import StateVisitor
from localstack.utils.collections import (
    remove_attributes,
    select_attributes,
    select_from_typed_dict,
)
from localstack.utils.json import clone
from localstack.utils.strings import long_uid, short_uid

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


def find_stack_instance(stack_set: StackSet, account: str, region: str):
    for instance in stack_set.stack_instances:
        if instance.metadata["Account"] == account and instance.metadata["Region"] == region:
            return instance
    return None


def stack_not_found_error(stack_name: str):
    # FIXME
    raise ValidationError("Stack with id %s does not exist" % stack_name)


def not_found_error(message: str):
    # FIXME
    raise ResourceNotFoundException(message)


class ResourceNotFoundException(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("ResourceNotFoundException", status_code=404, message=message)


class InternalFailure(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InternalFailure", status_code=500, message=message, sender_fault=False)


class CloudformationProvider(CloudformationApi):
    def _stack_status_is_active(self, stack_status: str) -> bool:
        return stack_status not in [StackStatus.DELETE_COMPLETE]

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(cloudformation_stores)

    @handler("CreateStack", expand=False)
    def create_stack(self, context: RequestContext, request: CreateStackInput) -> CreateStackOutput:
        # TODO: test what happens when both TemplateUrl and Body are specified
        state = get_cloudformation_store(context.account_id, context.region)

        stack_name = request.get("StackName")

        # get stacks by name
        active_stack_candidates = [
            s
            for s in state.stacks.values()
            if s.stack_name == stack_name and self._stack_status_is_active(s.status)
        ]

        # TODO: fix/implement this code path
        #   this needs more investigation how Cloudformation handles it (e.g. normal stack create or does it create a separate changeset?)
        # REVIEW_IN_PROGRESS is another special status
        # in this case existing changesets are set to obsolete and the stack is created
        # review_stack_candidates = [s for s in stack_candidates if s.status == StackStatus.REVIEW_IN_PROGRESS]
        # if review_stack_candidates:
        # set changesets to obsolete
        # for cs in review_stack_candidates[0].change_sets:
        #     cs.execution_status = ExecutionStatus.OBSOLETE

        if active_stack_candidates:
            raise AlreadyExistsException(f"Stack [{stack_name}] already exists")

        template_body = request.get("TemplateBody") or ""
        if len(template_body) > 51200:
            raise ValidationError(
                f'1 validation error detected: Value \'{request["TemplateBody"]}\' at \'templateBody\' '
                "failed to satisfy constraint: Member must have length less than or equal to 51200"
            )
        api_utils.prepare_template_body(request)  # TODO: avoid mutating request directly

        template = template_preparer.parse_template(request["TemplateBody"])

        stack_name = template["StackName"] = request.get("StackName")
        if api_utils.validate_stack_name(stack_name) is False:
            raise ValidationError(
                f"1 validation error detected: Value '{stack_name}' at 'stackName' failed to satisfy constraint:\
                Member must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*|arn:[-a-zA-Z0-9:/._+]*"
            )

        if (
            "CAPABILITY_AUTO_EXPAND" not in request.get("Capabilities", [])
            and "Transform" in template.keys()
        ):
            raise InsufficientCapabilitiesException(
                "Requires capabilities : [CAPABILITY_AUTO_EXPAND]"
            )

        # resolve stack parameters
        new_parameters = param_resolver.convert_stack_parameters_to_dict(request.get("Parameters"))
        parameter_declarations = param_resolver.extract_stack_parameter_declarations(template)
        resolved_parameters = param_resolver.resolve_parameters(
            account_id=context.account_id,
            region_name=context.region,
            parameter_declarations=parameter_declarations,
            new_parameters=new_parameters,
            old_parameters={},
        )

        # handle conditions
        stack = Stack(context.account_id, context.region, request, template)

        try:
            template = template_preparer.transform_template(
                context.account_id,
                context.region,
                template,
                stack.stack_name,
                stack.resources,
                stack.mappings,
                {},  # TODO
                resolved_parameters,
            )
        except FailedTransformationException as e:
            stack.add_stack_event(
                stack.stack_name,
                stack.stack_id,
                status="ROLLBACK_IN_PROGRESS",
                status_reason=e.message,
            )
            stack.set_stack_status("ROLLBACK_COMPLETE")
            state.stacks[stack.stack_id] = stack
            return CreateStackOutput(StackId=stack.stack_id)

        # perform basic static analysis on the template
        for validation_fn in DEFAULT_TEMPLATE_VALIDATIONS:
            validation_fn(template)

        stack = Stack(context.account_id, context.region, request, template)

        # resolve conditions
        raw_conditions = template.get("Conditions", {})
        resolved_stack_conditions = resolve_stack_conditions(
            account_id=context.account_id,
            region_name=context.region,
            conditions=raw_conditions,
            parameters=resolved_parameters,
            mappings=stack.mappings,
            stack_name=stack_name,
        )
        stack.set_resolved_stack_conditions(resolved_stack_conditions)

        stack.set_resolved_parameters(resolved_parameters)
        stack.template_body = json.dumps(template)
        state.stacks[stack.stack_id] = stack
        LOG.debug(
            'Creating stack "%s" with %s resources ...',
            stack.stack_name,
            len(stack.template_resources),
        )
        deployer = template_deployer.TemplateDeployer(context.account_id, context.region, stack)
        try:
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
        deletion_mode: DeletionMode = None,
        **kwargs,
    ) -> None:
        stack = find_active_stack_by_name_or_id(context.account_id, context.region, stack_name)
        if not stack:
            # aws will silently ignore invalid stack names - we should do the same
            return
        deployer = template_deployer.TemplateDeployer(context.account_id, context.region, stack)
        deployer.delete_stack()

    @handler("UpdateStack", expand=False)
    def update_stack(
        self,
        context: RequestContext,
        request: UpdateStackInput,
    ) -> UpdateStackOutput:
        stack_name = request.get("StackName")
        stack = find_stack(context.account_id, context.region, stack_name)
        if not stack:
            return not_found_error(f'Unable to update non-existing stack "{stack_name}"')

        api_utils.prepare_template_body(request)
        template = template_preparer.parse_template(request["TemplateBody"])

        if (
            "CAPABILITY_AUTO_EXPAND" not in request.get("Capabilities", [])
            and "Transform" in template.keys()
        ):
            raise InsufficientCapabilitiesException(
                "Requires capabilities : [CAPABILITY_AUTO_EXPAND]"
            )

        new_parameters: dict[str, Parameter] = param_resolver.convert_stack_parameters_to_dict(
            request.get("Parameters")
        )
        parameter_declarations = param_resolver.extract_stack_parameter_declarations(template)
        resolved_parameters = param_resolver.resolve_parameters(
            account_id=context.account_id,
            region_name=context.region,
            parameter_declarations=parameter_declarations,
            new_parameters=new_parameters,
            old_parameters=stack.resolved_parameters,
        )

        resolved_stack_conditions = resolve_stack_conditions(
            account_id=context.account_id,
            region_name=context.region,
            conditions=template.get("Conditions", {}),
            parameters=resolved_parameters,
            mappings=template.get("Mappings", {}),
            stack_name=stack_name,
        )

        raw_new_template = copy.deepcopy(template)
        try:
            template = template_preparer.transform_template(
                context.account_id,
                context.region,
                template,
                stack.stack_name,
                stack.resources,
                stack.mappings,
                resolved_stack_conditions,
                resolved_parameters,
            )
            processed_template = copy.deepcopy(
                template
            )  # copying it here since it's being mutated somewhere downstream
        except FailedTransformationException as e:
            stack.add_stack_event(
                stack.stack_name,
                stack.stack_id,
                status="ROLLBACK_IN_PROGRESS",
                status_reason=e.message,
            )
            stack.set_stack_status("ROLLBACK_COMPLETE")
            return CreateStackOutput(StackId=stack.stack_id)

        # perform basic static analysis on the template
        for validation_fn in DEFAULT_TEMPLATE_VALIDATIONS:
            validation_fn(template)

        # update the template
        stack.template_original = template

        deployer = template_deployer.TemplateDeployer(context.account_id, context.region, stack)
        # TODO: there shouldn't be a "new" stack on update
        new_stack = Stack(
            context.account_id, context.region, request, template, request["TemplateBody"]
        )
        new_stack.set_resolved_parameters(resolved_parameters)
        stack.set_resolved_parameters(resolved_parameters)
        stack.set_resolved_stack_conditions(resolved_stack_conditions)
        try:
            deployer.update_stack(new_stack)
        except NoStackUpdates as e:
            stack.set_stack_status("UPDATE_COMPLETE")
            if raw_new_template != processed_template:
                # processed templates seem to never return an exception here
                return UpdateStackOutput(StackId=stack.stack_id)
            raise ValidationError(str(e))
        except Exception as e:
            stack.set_stack_status("UPDATE_FAILED")
            msg = f'Unable to update stack "{stack_name}": {e}'
            LOG.exception("%s", msg)
            raise ValidationError(msg) from e

        return UpdateStackOutput(StackId=stack.stack_id)

    @handler("DescribeStacks")
    def describe_stacks(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeStacksOutput:
        # TODO: test & implement pagination
        state = get_cloudformation_store(context.account_id, context.region)

        if stack_name:
            if ARN_STACK_REGEX.match(stack_name):
                # we can get the stack directly since we index the store by ARN/stackID
                stack = state.stacks.get(stack_name)
                stacks = [stack.describe_details()] if stack else []
            else:
                # otherwise we have to find the active stack with the given name
                stack_candidates: list[Stack] = [
                    s for stack_arn, s in state.stacks.items() if s.stack_name == stack_name
                ]
                active_stack_candidates = [
                    s for s in stack_candidates if self._stack_status_is_active(s.status)
                ]
                stacks = [s.describe_details() for s in active_stack_candidates]
        else:
            # return all active stacks
            stack_list = list(state.stacks.values())
            stacks = [
                s.describe_details() for s in stack_list if self._stack_status_is_active(s.status)
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
        **kwargs,
    ) -> ListStacksOutput:
        state = get_cloudformation_store(context.account_id, context.region)

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
        **kwargs,
    ) -> GetTemplateOutput:
        if change_set_name:
            stack = find_change_set(
                context.account_id, context.region, stack_name=stack_name, cs_name=change_set_name
            )
        else:
            stack = find_stack(context.account_id, context.region, stack_name)
        if not stack:
            return stack_not_found_error(stack_name)

        if template_stage == TemplateStage.Processed and "Transform" in stack.template_body:
            copy_template = clone(stack.template_original)
            copy_template.pop("ChangeSetName", None)
            copy_template.pop("StackName", None)
            for resource in copy_template.get("Resources", {}).values():
                resource.pop("LogicalResourceId", None)
            template_body = json.dumps(copy_template)
        else:
            template_body = stack.template_body

        return GetTemplateOutput(
            TemplateBody=template_body,
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
            stack = find_stack(context.account_id, context.region, stack_name)
            if not stack:
                return stack_not_found_error(stack_name)
            template = stack.template
        else:
            api_utils.prepare_template_body(request)
            template = template_preparer.parse_template(request["TemplateBody"])
            request["StackName"] = "tmp-stack"
            stack = Stack(context.account_id, context.region, request, template)

        result: GetTemplateSummaryOutput = stack.describe_details()

        # build parameter declarations
        result["Parameters"] = list(
            param_resolver.extract_stack_parameter_declarations(template).values()
        )

        id_summaries = defaultdict(list)
        for resource_id, resource in stack.template_resources.items():
            res_type = resource["Type"]
            id_summaries[res_type].append(resource_id)

        result["ResourceTypes"] = list(id_summaries.keys())
        result["ResourceIdentifierSummaries"] = [
            {"ResourceType": key, "LogicalResourceIds": values}
            for key, values in id_summaries.items()
        ]
        result["Metadata"] = stack.template.get("Metadata")
        result["Version"] = stack.template.get("AWSTemplateFormatVersion", "2010-09-09")
        # these do not appear in the output
        result.pop("Capabilities", None)

        return select_from_typed_dict(GetTemplateSummaryOutput, result)

    def update_termination_protection(
        self,
        context: RequestContext,
        enable_termination_protection: EnableTerminationProtection,
        stack_name: StackNameOrId,
        **kwargs,
    ) -> UpdateTerminationProtectionOutput:
        stack = find_stack(context.account_id, context.region, stack_name)
        if not stack:
            raise ValidationError(f"Stack '{stack_name}' does not exist.")
        stack.metadata["EnableTerminationProtection"] = enable_termination_protection
        return UpdateTerminationProtectionOutput(StackId=stack.stack_id)

    @handler("CreateChangeSet", expand=False)
    def create_change_set(
        self, context: RequestContext, request: CreateChangeSetInput
    ) -> CreateChangeSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)

        req_params = request
        change_set_type = req_params.get("ChangeSetType", "UPDATE")
        stack_name = req_params.get("StackName")
        change_set_name = req_params.get("ChangeSetName")
        template_body = req_params.get("TemplateBody")
        # s3 or secretsmanager url
        template_url = req_params.get("TemplateURL")

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

        # this is intentionally not in a util yet. Let's first see how the different operations deal with these before generalizing
        # handle ARN stack_name here (not valid for initial CREATE, since stack doesn't exist yet)
        if ARN_STACK_REGEX.match(stack_name):
            if not (stack := state.stacks.get(stack_name)):
                raise ValidationError(f"Stack '{stack_name}' does not exist.")
        else:
            # stack name specified, so fetch the stack by name
            stack_candidates: list[Stack] = [
                s for stack_arn, s in state.stacks.items() if s.stack_name == stack_name
            ]
            active_stack_candidates = [
                s for s in stack_candidates if self._stack_status_is_active(s.status)
            ]

            # on a CREATE an empty Stack should be generated if we didn't find an active one
            if not active_stack_candidates and change_set_type == ChangeSetType.CREATE:
                empty_stack_template = dict(template)
                empty_stack_template["Resources"] = {}
                req_params_copy = clone_stack_params(req_params)
                stack = Stack(
                    context.account_id,
                    context.region,
                    req_params_copy,
                    empty_stack_template,
                    template_body=template_body,
                )
                state.stacks[stack.stack_id] = stack
                stack.set_stack_status("REVIEW_IN_PROGRESS")
            else:
                if not active_stack_candidates:
                    raise ValidationError(f"Stack '{stack_name}' does not exist.")
                stack = active_stack_candidates[0]

        # TODO: test if rollback status is allowed as well
        if (
            change_set_type == ChangeSetType.CREATE
            and stack.status != StackStatus.REVIEW_IN_PROGRESS
        ):
            raise ValidationError(
                f"Stack [{stack_name}] already exists and cannot be created again with the changeSet [{change_set_name}]."
            )

        old_parameters: dict[str, Parameter] = {}
        match change_set_type:
            case ChangeSetType.UPDATE:
                # add changeset to existing stack
                old_parameters = {
                    k: strip_parameter_type(v) for k, v in stack.resolved_parameters.items()
                }
            case ChangeSetType.IMPORT:
                raise NotImplementedError()  # TODO: implement importing resources
            case ChangeSetType.CREATE:
                pass
            case _:
                msg = (
                    f"1 validation error detected: Value '{change_set_type}' at 'changeSetType' failed to satisfy "
                    f"constraint: Member must satisfy enum value set: [IMPORT, UPDATE, CREATE] "
                )
                raise ValidationError(msg)

        # resolve parameters
        new_parameters: dict[str, Parameter] = param_resolver.convert_stack_parameters_to_dict(
            request.get("Parameters")
        )
        parameter_declarations = param_resolver.extract_stack_parameter_declarations(template)
        resolved_parameters = param_resolver.resolve_parameters(
            account_id=context.account_id,
            region_name=context.region,
            parameter_declarations=parameter_declarations,
            new_parameters=new_parameters,
            old_parameters=old_parameters,
        )

        # TODO: remove this when fixing Stack.resources and transformation order
        #   currently we need to create a stack with existing resources + parameters so that resolve refs recursively in here will work.
        #   The correct way to do it would be at a later stage anyway just like a normal intrinsic function
        req_params_copy = clone_stack_params(req_params)
        temp_stack = Stack(context.account_id, context.region, req_params_copy, template)
        temp_stack.set_resolved_parameters(resolved_parameters)

        # TODO: everything below should be async
        # apply template transformations
        transformed_template = template_preparer.transform_template(
            context.account_id,
            context.region,
            template,
            stack_name=temp_stack.stack_name,
            resources=temp_stack.resources,
            mappings=temp_stack.mappings,
            conditions={},  # TODO: we don't have any resolved conditions yet at this point but we need the conditions because of the samtranslator...
            resolved_parameters=resolved_parameters,
        )

        # perform basic static analysis on the template
        for validation_fn in DEFAULT_TEMPLATE_VALIDATIONS:
            validation_fn(template)

        # create change set for the stack and apply changes
        change_set = StackChangeSet(
            context.account_id, context.region, stack, req_params, transformed_template
        )
        # only set parameters for the changeset, then switch to stack on execute_change_set
        change_set.set_resolved_parameters(resolved_parameters)
        change_set.template_body = template_body

        # TODO: evaluate conditions
        raw_conditions = transformed_template.get("Conditions", {})
        resolved_stack_conditions = resolve_stack_conditions(
            account_id=context.account_id,
            region_name=context.region,
            conditions=raw_conditions,
            parameters=resolved_parameters,
            mappings=temp_stack.mappings,
            stack_name=stack_name,
        )
        change_set.set_resolved_stack_conditions(resolved_stack_conditions)

        # a bit gross but use the template ordering to validate missing resources
        try:
            order_resources(
                transformed_template["Resources"],
                resolved_parameters=resolved_parameters,
                resolved_conditions=resolved_stack_conditions,
            )
        except NoResourceInStack as e:
            raise ValidationError(str(e)) from e

        deployer = template_deployer.TemplateDeployer(
            context.account_id, context.region, change_set
        )
        changes = deployer.construct_changes(
            stack,
            change_set,
            change_set_id=change_set.change_set_id,
            append_to_changeset=True,
            filter_unchanged_resources=True,
        )
        stack.change_sets.append(change_set)
        if not changes:
            change_set.metadata["Status"] = "FAILED"
            change_set.metadata["ExecutionStatus"] = "UNAVAILABLE"
            change_set.metadata["StatusReason"] = (
                "The submitted information didn't contain changes. Submit different information to create a change set."
            )
        else:
            change_set.metadata["Status"] = (
                "CREATE_COMPLETE"  # technically for some time this should first be CREATE_PENDING
            )
            change_set.metadata["ExecutionStatus"] = (
                "AVAILABLE"  # technically for some time this should first be UNAVAILABLE
            )

        return CreateChangeSetOutput(StackId=change_set.stack_id, Id=change_set.change_set_id)

    @handler("DescribeChangeSet")
    def describe_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        next_token: NextToken = None,
        include_property_values: IncludePropertyValues = None,
        **kwargs,
    ) -> DescribeChangeSetOutput:
        # TODO add support for include_property_values
        # only relevant if change_set_name isn't an ARN
        if not ARN_CHANGESET_REGEX.match(change_set_name):
            if not stack_name:
                raise ValidationError(
                    "StackName must be specified if ChangeSetName is not specified as an ARN."
                )

            stack = find_stack(context.account_id, context.region, stack_name)
            if not stack:
                raise ValidationError(f"Stack [{stack_name}] does not exist")

        change_set = find_change_set(
            context.account_id, context.region, change_set_name, stack_name=stack_name
        )
        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")

        attrs = [
            "ChangeSetType",
            "StackStatus",
            "LastUpdatedTime",
            "DisableRollback",
            "EnableTerminationProtection",
            "Transform",
        ]
        result = remove_attributes(deepcopy(change_set.metadata), attrs)
        # TODO: replace this patch with a better solution
        result["Parameters"] = [strip_parameter_type(p) for p in result.get("Parameters", [])]
        return result

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        **kwargs,
    ) -> DeleteChangeSetOutput:
        # only relevant if change_set_name isn't an ARN
        if not ARN_CHANGESET_REGEX.match(change_set_name):
            if not stack_name:
                raise ValidationError(
                    "StackName must be specified if ChangeSetName is not specified as an ARN."
                )

            stack = find_stack(context.account_id, context.region, stack_name)
            if not stack:
                raise ValidationError(f"Stack [{stack_name}] does not exist")

        change_set = find_change_set(
            context.account_id, context.region, change_set_name, stack_name=stack_name
        )
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
        retain_except_on_create: RetainExceptOnCreate = None,
        **kwargs,
    ) -> ExecuteChangeSetOutput:
        change_set = find_change_set(
            context.account_id,
            context.region,
            change_set_name,
            stack_name=stack_name,
            active_only=True,
        )
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
        deployer = template_deployer.TemplateDeployer(
            context.account_id, context.region, change_set.stack
        )
        try:
            deployer.apply_change_set(change_set)
            change_set.stack.metadata["ChangeSetId"] = change_set.change_set_id
        except NoStackUpdates:
            # TODO: parity-check if this exception should be re-raised or swallowed
            raise ValidationError("No updates to be performed for stack change set")

        return ExecuteChangeSetOutput()

    @handler("ListChangeSets")
    def list_change_sets(
        self,
        context: RequestContext,
        stack_name: StackNameOrId,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListChangeSetsOutput:
        stack = find_stack(context.account_id, context.region, stack_name)
        if not stack:
            return not_found_error(f'Unable to find stack "{stack_name}"')
        result = [cs.metadata for cs in stack.change_sets]
        return ListChangeSetsOutput(Summaries=result)

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken = None, **kwargs
    ) -> ListExportsOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        return ListExportsOutput(Exports=state.exports)

    @handler("ListImports")
    def list_imports(
        self,
        context: RequestContext,
        export_name: ExportName,
        next_token: NextToken = None,
        **kwargs,
    ) -> ListImportsOutput:
        state = get_cloudformation_store(context.account_id, context.region)

        importing_stack_names = []
        for stack in state.stacks.values():
            if export_name in stack.imports:
                importing_stack_names.append(stack.stack_name)

        return ListImportsOutput(Imports=importing_stack_names)

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeStackEventsOutput:
        if stack_name is None:
            raise ValidationError(
                "1 validation error detected: Value null at 'stackName' failed to satisfy constraint: Member must not be null"
            )

        stack = find_active_stack_by_name_or_id(context.account_id, context.region, stack_name)
        if not stack:
            stack = find_stack_by_id(
                account_id=context.account_id, region_name=context.region, stack_id=stack_name
            )
        if not stack:
            raise ValidationError(f"Stack [{stack_name}] does not exist")
        return DescribeStackEventsOutput(StackEvents=stack.events)

    @handler("DescribeStackResource")
    def describe_stack_resource(
        self,
        context: RequestContext,
        stack_name: StackName,
        logical_resource_id: LogicalResourceId,
        **kwargs,
    ) -> DescribeStackResourceOutput:
        stack = find_stack(context.account_id, context.region, stack_name)

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
        **kwargs,
    ) -> DescribeStackResourcesOutput:
        if physical_resource_id and stack_name:
            raise ValidationError("Cannot specify both StackName and PhysicalResourceId")
        # TODO: filter stack by PhysicalResourceId!
        stack = find_stack(context.account_id, context.region, stack_name)
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
        self, context: RequestContext, stack_name: StackName, next_token: NextToken = None, **kwargs
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
        state = get_cloudformation_store(context.account_id, context.region)
        stack_set = StackSet(request)
        stack_set_id = f"{stack_set.stack_set_name}:{long_uid()}"
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
        **kwargs,
    ) -> DescribeStackSetOperationOutput:
        state = get_cloudformation_store(context.account_id, context.region)

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
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        call_as: CallAs = None,
        **kwargs,
    ) -> DescribeStackSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
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
        state = get_cloudformation_store(context.account_id, context.region)
        result = [sset.metadata for sset in state.stack_sets.values()]
        return ListStackSetsOutput(Summaries=result)

    @handler("UpdateStackSet", expand=False)
    def update_stack_set(
        self, context: RequestContext, request: UpdateStackSetInput
    ) -> UpdateStackSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
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
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        call_as: CallAs = None,
        **kwargs,
    ) -> DeleteStackSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        stack_set = [
            sset for sset in state.stack_sets.values() if sset.stack_set_name == stack_set_name
        ]

        if not stack_set:
            return not_found_error(f'Stack set named "{stack_set_name}" does not exist')

        # TODO: add a check for remaining stack instances

        for instance in stack_set[0].stack_instances:
            deployer = template_deployer.TemplateDeployer(
                context.account_id, context.region, instance.stack
            )
            deployer.delete_stack()
        return DeleteStackSetOutput()

    @handler("CreateStackInstances", expand=False)
    def create_stack_instances(
        self,
        context: RequestContext,
        request: CreateStackInstancesInput,
    ) -> CreateStackInstancesOutput:
        state = get_cloudformation_store(context.account_id, context.region)

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
                LOG.debug(
                    'Deploying instance for stack set "%s" in account: %s region %s',
                    set_name,
                    account,
                    region,
                )
                cf_client = connect_to(aws_access_key_id=account, region_name=region).cloudformation
                kwargs = select_attributes(sset_meta, ["TemplateBody"]) or select_attributes(
                    sset_meta, ["TemplateURL"]
                )
                stack_name = f"sset-{set_name}-{account}"

                # skip creation of existing stacks
                if find_stack(context.account_id, context.region, stack_name):
                    continue

                result = cf_client.create_stack(StackName=stack_name, **kwargs)
                stacks_to_await.append((stack_name, account, region))
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
        for stack_name, account_id, region_name in stacks_to_await:
            client = connect_to(
                aws_access_key_id=account_id, region_name=region_name
            ).cloudformation
            client.get_waiter("stack_create_complete").wait(StackName=stack_name)

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
        state = get_cloudformation_store(context.account_id, context.region)
        stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')

        stack_set = stack_set[0]
        result = [inst.metadata for inst in stack_set.stack_instances]
        return ListStackInstancesOutput(Summaries=result)

    @handler("DeleteStackInstances", expand=False)
    def delete_stack_instances(
        self,
        context: RequestContext,
        request: DeleteStackInstancesInput,
    ) -> DeleteStackInstancesOutput:
        op_id = request.get("OperationId") or short_uid()

        accounts = request["Accounts"]
        regions = request["Regions"]

        state = get_cloudformation_store(context.account_id, context.region)
        stack_sets = state.stack_sets.values()

        set_name = request.get("StackSetName")
        stack_set = next((sset for sset in stack_sets if sset.stack_set_name == set_name), None)

        if not stack_set:
            return not_found_error(f'Stack set named "{set_name}" does not exist')

        for account in accounts:
            for region in regions:
                instance = find_stack_instance(stack_set, account, region)
                if instance:
                    stack_set.stack_instances.remove(instance)

        # record operation
        operation = {
            "OperationId": op_id,
            "StackSetId": stack_set.metadata["StackSetId"],
            "Action": "DELETE",
            "Status": "SUCCEEDED",
        }
        stack_set.operations[op_id] = operation

        return DeleteStackInstancesOutput(OperationId=op_id)

    @handler("RegisterType", expand=False)
    def register_type(
        self,
        context: RequestContext,
        request: RegisterTypeInput,
    ) -> RegisterTypeOutput:
        return RegisterTypeOutput()
