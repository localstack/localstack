import logging
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
from localstack.services.cloudformation.engine import template_preparer
from localstack.services.cloudformation.engine.parameters import mask_no_echo, strip_parameter_type
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
)
from localstack.services.cloudformation.stores import (
    find_change_set,
    get_cloudformation_store,
)
from localstack.services.cloudformation.v2.entities import Stack, StackChangeSet

LOG = logging.getLogger(__name__)


def is_stack_arn(stack_name_or_id: str) -> bool:
    return ARN_STACK_REGEX.match(stack_name_or_id) is not None


def is_changeset_arn(change_set_name_or_id: str) -> bool:
    return ARN_CHANGESET_REGEX.match(change_set_name_or_id) is not None


class CloudformationProviderV2(CloudformationProvider):
    @handler("CreateChangeSet", expand=False)
    def create_change_set(
        self, context: RequestContext, request: CreateChangeSetInput
    ) -> CreateChangeSetOutput:
        try:
            stack_name = request["StackName"]
        except KeyError:
            # TODO: proper exception
            raise ValidationError("StackName must be specified")
        try:
            change_set_name = request["ChangeSetName"]
        except KeyError:
            # TODO: proper exception
            raise ValidationError("StackName must be specified")

        state = get_cloudformation_store(context.account_id, context.region)

        change_set_type = request.get("ChangeSetType", "UPDATE")
        template_body = request.get("TemplateBody")
        # s3 or secretsmanager url
        template_url = request.get("TemplateURL")

        # validate and resolve template
        if template_body and template_url:
            raise ValidationError(
                "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
            )  # TODO: check proper message

        if not template_body and not template_url:
            raise ValidationError(
                "Specify exactly one of 'TemplateBody' or 'TemplateUrl'"
            )  # TODO: check proper message

        template_body = api_utils.extract_template_body(request)
        structured_template = template_preparer.parse_template(template_body)

        # this is intentionally not in a util yet. Let's first see how the different operations deal with these before generalizing
        # handle ARN stack_name here (not valid for initial CREATE, since stack doesn't exist yet)
        if is_stack_arn(stack_name):
            stack = state.stacks.get(stack_name)
            if not stack:
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
                stack = Stack(
                    context.account_id,
                    context.region,
                    request,
                    structured_template,
                    template_body=template_body,
                )
                state.stacks_v2[stack.stack_id] = stack
            else:
                if not active_stack_candidates:
                    raise ValidationError(f"Stack '{stack_name}' does not exist.")
                stack = active_stack_candidates[0]

        stack.set_stack_status("REVIEW_IN_PROGRESS")

        # TODO: test if rollback status is allowed as well
        if (
            change_set_type == ChangeSetType.CREATE
            and stack.status != StackStatus.REVIEW_IN_PROGRESS
        ):
            raise ValidationError(
                f"Stack [{stack_name}] already exists and cannot be created again with the changeSet [{change_set_name}]."
            )

        before_parameters: dict[str, Parameter] | None = None
        match change_set_type:
            case ChangeSetType.UPDATE:
                before_parameters = stack.resolved_parameters
                # add changeset to existing stack
                # old_parameters = {
                #     k: mask_no_echo(strip_parameter_type(v))
                #     for k, v in stack.resolved_parameters.items()
                # }
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

        # TDOO: transformations

        # TODO: reconsider the way parameters are modelled in the update graph process.
        #  The options might be reduce to using the current style, or passing the extra information
        #  as a metadata object. The choice should be made considering when the extra information
        #  is needed for the update graph building, or only looked up in downstream tasks (metadata).
        request_parameters = request.get("Parameters", list())
        # TODO: handle parameter defaults and resolution
        after_parameters: dict[str, Any] = {
            parameter["ParameterKey"]: parameter["ParameterValue"]
            for parameter in request_parameters
        }

        # TODO: update this logic to always pass the clean template object if one exists. The
        #  current issue with relaying on stack.template_original is that this appears to have
        #  its parameters and conditions populated.
        before_template = None
        if change_set_type == ChangeSetType.UPDATE:
            before_template = stack.template
        after_template = structured_template

        # create change set for the stack and apply changes
        change_set = StackChangeSet(stack, request)

        # only set parameters for the changeset, then switch to stack on execute_change_set
        change_set.populate_update_graph(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )
        stack.change_set_id = change_set.change_set_id
        state.change_sets[change_set.change_set_id] = change_set

        return CreateChangeSetOutput(StackId=stack.stack_id, Id=change_set.change_set_id)

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
        state = get_cloudformation_store(context.account_id, context.region)

        change_set: StackChangeSet | None = None
        if is_changeset_arn(change_set_name):
            change_set = state.change_sets[change_set_name]
        else:
            if stack_name is not None:
                stack: Stack | None = None
                if is_stack_arn(stack_name):
                    stack = state.stacks_v2[stack_name]
                else:
                    for stack_candidate in state.stacks_v2.values():
                        # TODO: check for active stacks
                        if stack_candidate.stack_name == stack_name:  # and stack.status
                            stack = stack_candidate
                            break

                if not stack:
                    raise NotImplementedError(f"no stack found for change set {change_set_name}")

                for change_set_id in stack.change_set_ids:
                    change_set_candidate = state.change_sets[change_set_id]
                    if change_set_candidate.change_set_name == change_set_name:
                        change_set = change_set_candidate
                        break
            else:
                raise NotImplementedError

        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")

        change_set_describer = ChangeSetModelDescriber(
            node_template=change_set.update_graph,
            include_property_values=bool(include_property_values),
        )
        changes: Changes = change_set_describer.get_changes()

        result = {
            "ChangeSetType": change_set.change_set_type,
            "StackStatus": change_set.stack.status,
            "LastUpdatedTime": "",
            "DisableRollback": "",
            "EnableTerminationProtection": "",
            "Transform": "",
            "Parameters": [
                mask_no_echo(strip_parameter_type(p)) for p in change_set.stack.resolved_parameters
            ],
            "Changes": changes,
        }
        return result
