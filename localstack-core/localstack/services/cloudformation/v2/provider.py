import json
import logging
from copy import deepcopy
from typing import Any

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.cloudformation import (
    Changes,
    ChangeSetNameOrId,
    ChangeSetNotFoundException,
    ChangeSetType,
    ClientRequestToken,
    CreateChangeSetInput,
    CreateChangeSetOutput,
    DescribeChangeSetOutput,
    DisableRollback,
    ExecuteChangeSetOutput,
    ExecutionStatus,
    IncludePropertyValues,
    InvalidChangeSetStatusException,
    NextToken,
    Parameter,
    RetainExceptOnCreate,
    StackNameOrId,
    StackStatus,
)
from localstack.services.cloudformation import api_utils
from localstack.services.cloudformation.engine import parameters as param_resolver
from localstack.services.cloudformation.engine import template_deployer, template_preparer
from localstack.services.cloudformation.engine.entities import Stack, StackChangeSet
from localstack.services.cloudformation.engine.parameters import mask_no_echo, strip_parameter_type
from localstack.services.cloudformation.engine.resource_ordering import (
    NoResourceInStack,
    order_resources,
)
from localstack.services.cloudformation.engine.template_utils import resolve_stack_conditions
from localstack.services.cloudformation.engine.v2.change_set_model_describer import (
    ChangeSetModelDescriber,
)
from localstack.services.cloudformation.engine.v2.change_set_model_executor import (
    ChangeSetModelExecutor,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.provider import (
    ARN_CHANGESET_REGEX,
    ARN_STACK_REGEX,
    CloudformationProvider,
    clone_stack_params,
)
from localstack.services.cloudformation.stores import (
    find_change_set,
    find_stack,
    get_cloudformation_store,
)
from localstack.utils.collections import remove_attributes

LOG = logging.getLogger(__name__)


class CloudformationProviderV2(CloudformationProvider):
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
                    k: mask_no_echo(strip_parameter_type(v))
                    for k, v in stack.resolved_parameters.items()
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

        # TODO: reconsider the way parameters are modelled in the update graph process.
        #  The options might be reduce to using the current style, or passing the extra information
        #  as a metadata object. The choice should be made considering when the extra information
        #  is needed for the update graph building, or only looked up in downstream tasks (metadata).
        request_parameters = request.get("Parameters", list())
        after_parameters: dict[str, Any] = {
            parameter["ParameterKey"]: parameter["ParameterValue"]
            for parameter in request_parameters
        }
        before_parameters: dict[str, Any] = {
            parameter["ParameterKey"]: parameter["ParameterValue"]
            for parameter in old_parameters.values()
        }

        # TODO: update this logic to always pass the clean template object if one exists. The
        #  current issue with relaying on stack.template_original is that this appears to have
        #  its parameters and conditions populated.
        before_template = None
        if change_set_type == ChangeSetType.UPDATE:
            before_template = json.loads(
                stack.template_body
            )  # template_original is sometimes invalid
        after_template = template

        # create change set for the stack and apply changes
        change_set = StackChangeSet(
            context.account_id,
            context.region,
            stack,
            req_params,
            transformed_template,
            change_set_type=change_set_type,
        )
        # only set parameters for the changeset, then switch to stack on execute_change_set
        change_set.template_body = template_body
        change_set.populate_update_graph(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )

        # TODO: move this logic of condition resolution with metadata to the ChangeSetModelPreproc or Executor
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
        change_set.set_resolved_parameters(resolved_parameters)

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

    @handler("ExecuteChangeSet")
    def execute_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        client_request_token: ClientRequestToken | None = None,
        disable_rollback: DisableRollback | None = None,
        retain_except_on_create: RetainExceptOnCreate | None = None,
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
        if not change_set.update_graph:
            raise RuntimeError("Programming error: no update graph found for change set")

        change_set_executor = ChangeSetModelExecutor(
            change_set.update_graph,
            account_id=context.account_id,
            region=context.region,
            stack_name=change_set.stack.stack_name,
            stack_id=change_set.stack.stack_id,
        )
        new_resources = change_set_executor.execute()
        change_set.stack.set_stack_status(f"{change_set.change_set_type or 'UPDATE'}_COMPLETE")
        change_set.stack.resources = new_resources
        return ExecuteChangeSetOutput()

    @handler("DescribeChangeSet")
    def describe_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId | None = None,
        next_token: NextToken | None = None,
        include_property_values: IncludePropertyValues | None = None,
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

        change_set_describer = ChangeSetModelDescriber(
            node_template=change_set.update_graph,
            include_property_values=bool(include_property_values),
        )
        changes: Changes = change_set_describer.get_changes()

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
        result["Parameters"] = [
            mask_no_echo(strip_parameter_type(p)) for p in result.get("Parameters", [])
        ]
        result["Changes"] = changes
        return result
