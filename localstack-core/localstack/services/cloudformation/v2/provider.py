import copy
import json
import logging
import re
from collections import defaultdict
from datetime import UTC, datetime
from urllib.parse import urlencode

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.cloudformation import (
    AlreadyExistsException,
    CallAs,
    Changes,
    ChangeSetNameOrId,
    ChangeSetNotFoundException,
    ChangeSetStatus,
    ChangeSetType,
    ClientRequestToken,
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
    DescribeStacksOutput,
    DisableRollback,
    EnableTerminationProtection,
    ExecuteChangeSetOutput,
    ExecutionStatus,
    GetTemplateOutput,
    GetTemplateSummaryInput,
    GetTemplateSummaryOutput,
    IncludePropertyValues,
    InsufficientCapabilitiesException,
    InvalidChangeSetStatusException,
    ListExportsOutput,
    ListStackResourcesOutput,
    ListStacksOutput,
    LogicalResourceId,
    NextToken,
    Parameter,
    PhysicalResourceId,
    ResourceStatus,
    RetainExceptOnCreate,
    RetainResources,
    RoleARN,
    RollbackConfiguration,
    StackDriftInformation,
    StackDriftStatus,
    StackName,
    StackNameOrId,
    StackResourceDetail,
    StackResourceSummary,
    StackSetName,
    StackSetNotFoundException,
    StackSetOperation,
    StackSetOperationAction,
    StackSetOperationStatus,
    StackStatus,
    StackStatusFilter,
    TemplateStage,
    UpdateStackInput,
    UpdateStackOutput,
    UpdateTerminationProtectionOutput,
)
from localstack.aws.api.cloudformation import (
    Stack as ApiStack,
)
from localstack.aws.connect import connect_to
from localstack.services.cloudformation import api_utils
from localstack.services.cloudformation.engine import template_preparer
from localstack.services.cloudformation.engine.parameters import resolve_ssm_parameter
from localstack.services.cloudformation.engine.transformers import FailedTransformationException
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    ChangeType,
    UpdateModel,
)
from localstack.services.cloudformation.engine.v2.change_set_model_describer import (
    ChangeSetModelDescriber,
)
from localstack.services.cloudformation.engine.v2.change_set_model_executor import (
    ChangeSetModelExecutor,
)
from localstack.services.cloudformation.engine.v2.change_set_model_transform import (
    ChangeSetModelTransform,
)
from localstack.services.cloudformation.engine.v2.change_set_model_validator import (
    ChangeSetModelValidator,
)
from localstack.services.cloudformation.engine.validations import ValidationError
from localstack.services.cloudformation.provider import (
    ARN_CHANGESET_REGEX,
    ARN_STACK_REGEX,
    ARN_STACK_SET_REGEX,
    CloudformationProvider,
)
from localstack.services.cloudformation.stores import (
    CloudFormationStore,
    get_cloudformation_store,
)
from localstack.services.cloudformation.v2.entities import (
    ChangeSet,
    Stack,
    StackInstance,
    StackSet,
)
from localstack.services.cloudformation.v2.types import EngineParameter
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.collections import select_attributes
from localstack.utils.strings import short_uid
from localstack.utils.threads import start_worker_thread

LOG = logging.getLogger(__name__)

SSM_PARAMETER_TYPE_RE = re.compile(
    r"^AWS::SSM::Parameter::Value<(?P<listtype>List<)?(?P<innertype>[^>]+)>?>$"
)


def is_stack_arn(stack_name_or_id: str) -> bool:
    return ARN_STACK_REGEX.match(stack_name_or_id) is not None


def is_changeset_arn(change_set_name_or_id: str) -> bool:
    return ARN_CHANGESET_REGEX.match(change_set_name_or_id) is not None


def is_stack_set_arn(stack_set_name_or_id: str) -> bool:
    return ARN_STACK_SET_REGEX.match(stack_set_name_or_id) is not None


class StackNotFoundError(ValidationError):
    def __init__(self, stack_name_or_id: str, message_override: str | None = None):
        if message_override:
            super().__init__(message_override)
        else:
            if is_stack_arn(stack_name_or_id):
                super().__init__(f"Stack with id {stack_name_or_id} does not exist")
            else:
                super().__init__(f"Stack [{stack_name_or_id}] does not exist")


class StackSetNotFoundError(StackSetNotFoundException):
    def __init__(self, stack_set_name: str):
        super().__init__(f"StackSet {stack_set_name} not found")


def find_stack_v2(state: CloudFormationStore, stack_name: str | None) -> Stack | None:
    if stack_name:
        if is_stack_arn(stack_name):
            return state.stacks_v2[stack_name]
        else:
            stack_candidates = []
            for stack in state.stacks_v2.values():
                if stack.stack_name == stack_name and stack.status != StackStatus.DELETE_COMPLETE:
                    stack_candidates.append(stack)
            if len(stack_candidates) == 0:
                return None
            elif len(stack_candidates) > 1:
                raise RuntimeError("Programing error, duplicate stacks found")
            else:
                return stack_candidates[0]
    else:
        raise ValueError("No stack name specified when finding stack")


def find_change_set_v2(
    state: CloudFormationStore, change_set_name: str, stack_name: str | None = None
) -> ChangeSet | None:
    if is_changeset_arn(change_set_name):
        return state.change_sets.get(change_set_name)
    else:
        if stack_name is not None:
            stack = find_stack_v2(state, stack_name)
            if not stack:
                raise StackNotFoundError(stack_name)

            for change_set_id in stack.change_set_ids:
                change_set_candidate = state.change_sets[change_set_id]
                if change_set_candidate.change_set_name == change_set_name:
                    return change_set_candidate
        else:
            raise ValidationError(
                "StackName must be specified if ChangeSetName is not specified as an ARN."
            )


def find_stack_set_v2(state: CloudFormationStore, stack_set_name: str) -> StackSet | None:
    if is_stack_set_arn(stack_set_name):
        return state.stack_sets.get(stack_set_name)

    for stack_set in state.stack_sets_v2.values():
        if stack_set.stack_set_name == stack_set_name:
            return stack_set

    return None


def find_stack_instance(stack_set: StackSet, account: str, region: str) -> StackInstance | None:
    for instance in stack_set.stack_instances:
        if instance.account_id == account and instance.region_name == region:
            return instance
    return None


class CloudformationProviderV2(CloudformationProvider, ServiceLifecycleHook):
    def on_before_start(self):
        base = "https://github.com/localstack/localstack/issues/new"
        query_args = {
            "template": "bug-report.yml",
            "labels": ",".join(
                [
                    "aws:cloudformation:v2",
                    "status: triage needed",
                    "type: bug",
                ]
            ),
            "title": "CFNV2: ",
        }
        issue_url = "?".join([base, urlencode(query_args)])
        LOG.info(
            "You have opted in to the new CloudFormation deployment engine. "
            "You can opt in to using the old engine by setting PROVIDER_OVERRIDE_CLOUDFORMATION=legacy. "
            "If you experience issues, please submit a bug report at this URL: %s",
            issue_url,
        )

    @staticmethod
    def _resolve_parameters(
        template: dict | None, parameters: dict | None, account_id: str, region_name: str
    ) -> dict[str, EngineParameter]:
        template_parameters = template.get("Parameters", {})
        resolved_parameters = {}
        invalid_parameters = []
        for name, parameter in template_parameters.items():
            given_value = parameters.get(name)
            default_value = parameter.get("Default")
            resolved_parameter = EngineParameter(
                type_=parameter["Type"],
                given_value=given_value,
                default_value=default_value,
                no_echo=parameter.get("NoEcho"),
            )

            # TODO: support other parameter types
            if match := SSM_PARAMETER_TYPE_RE.match(parameter["Type"]):
                inner_type = match.group("innertype")
                is_list_type = match.group("listtype") is not None
                if is_list_type or inner_type == "CommaDelimitedList":
                    # list types
                    try:
                        resolved_value = resolve_ssm_parameter(
                            account_id, region_name, given_value or default_value
                        )
                        resolved_parameter["resolved_value"] = resolved_value.split(",")
                    except Exception:
                        raise ValidationError(
                            f"Parameter {name} should either have input value or default value"
                        )
                else:
                    try:
                        resolved_parameter["resolved_value"] = resolve_ssm_parameter(
                            account_id, region_name, given_value or default_value
                        )
                    except Exception:
                        raise ValidationError(
                            f"Parameter {name} should either have input value or default value"
                        )
            elif given_value is None and default_value is None:
                invalid_parameters.append(name)
                continue

            resolved_parameters[name] = resolved_parameter

        if invalid_parameters:
            raise ValidationError(f"Parameters: [{','.join(invalid_parameters)}] must have values")

        for name, parameter in resolved_parameters.items():
            if (
                parameter.get("resolved_value") is None
                and parameter.get("given_value") is None
                and parameter.get("default_value") is None
            ):
                raise ValidationError(
                    f"Parameter {name} should either have input value or default value"
                )

        return resolved_parameters

    @classmethod
    def _setup_change_set_model(
        cls,
        change_set: ChangeSet,
        before_template: dict | None,
        after_template: dict | None,
        before_parameters: dict | None,
        after_parameters: dict | None,
        previous_update_model: UpdateModel | None = None,
    ):
        resolved_parameters = None
        if after_parameters is not None:
            resolved_parameters = cls._resolve_parameters(
                after_template,
                after_parameters,
                change_set.stack.account_id,
                change_set.stack.region_name,
            )

        change_set.resolved_parameters = resolved_parameters

        # Create and preprocess the update graph for this template update.
        change_set_model = ChangeSetModel(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=resolved_parameters,
        )
        raw_update_model: UpdateModel = change_set_model.get_update_model()
        # If there exists an update model which operated in the 'before' version of this change set,
        # port the runtime values computed for the before version into this latest update model.
        if previous_update_model:
            raw_update_model.before_runtime_cache.clear()
            raw_update_model.before_runtime_cache.update(previous_update_model.after_runtime_cache)
        change_set.set_update_model(raw_update_model)

        # Apply global transforms.
        # TODO: skip this process iff both versions of the template don't specify transform blocks.
        change_set_model_transform = ChangeSetModelTransform(
            change_set=change_set,
            before_parameters=before_parameters,
            after_parameters=resolved_parameters,
            before_template=before_template,
            after_template=after_template,
        )
        try:
            transformed_before_template, transformed_after_template = (
                change_set_model_transform.transform()
            )
        except FailedTransformationException as e:
            change_set.status = ChangeSetStatus.FAILED
            change_set.status_reason = e.message
            change_set.stack.set_stack_status(
                status=StackStatus.ROLLBACK_IN_PROGRESS, reason=e.message
            )
            change_set.stack.set_stack_status(status=StackStatus.CREATE_FAILED)
            return

        # Remodel the update graph after the applying the global transforms.
        change_set_model = ChangeSetModel(
            before_template=transformed_before_template,
            after_template=transformed_after_template,
            before_parameters=before_parameters,
            after_parameters=resolved_parameters,
        )
        update_model = change_set_model.get_update_model()
        # Bring the cache for the previous operations forward in the update graph for this version
        # of the templates. This enables downstream update graph visitors to access runtime
        # information computed whilst evaluating the previous version of this template, and during
        # the transformations.
        update_model.before_runtime_cache.update(raw_update_model.before_runtime_cache)
        update_model.after_runtime_cache.update(raw_update_model.after_runtime_cache)
        change_set.set_update_model(update_model)

        # perform validations
        validator = ChangeSetModelValidator(
            change_set=change_set,
        )
        validator.validate()

        # hacky
        if transform := raw_update_model.node_template.transform:
            if transform.global_transforms:
                # global transforms should always be considered "MODIFIED"
                update_model.node_template.change_type = ChangeType.MODIFIED
        change_set.processed_template = transformed_after_template

    @handler("CreateChangeSet", expand=False)
    def create_change_set(
        self, context: RequestContext, request: CreateChangeSetInput
    ) -> CreateChangeSetOutput:
        stack_name = request.get("StackName")
        if not stack_name:
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

        if len(template_body) > 51200 and not template_url:
            raise ValidationError(
                f"1 validation error detected: Value '{template_body}' at 'templateBody' "
                "failed to satisfy constraint: Member must have length less than or equal to 51200"
            )

        # this is intentionally not in a util yet. Let's first see how the different operations deal with these before generalizing
        # handle ARN stack_name here (not valid for initial CREATE, since stack doesn't exist yet)
        if is_stack_arn(stack_name):
            stack = state.stacks_v2.get(stack_name)
            if not stack:
                raise ValidationError(f"Stack '{stack_name}' does not exist.")
            stack.capabilities = request.get("Capabilities") or []
        else:
            # stack name specified, so fetch the stack by name
            stack_candidates: list[Stack] = [
                s for stack_arn, s in state.stacks_v2.items() if s.stack_name == stack_name
            ]
            active_stack_candidates = [s for s in stack_candidates if s.is_active()]

            # on a CREATE an empty Stack should be generated if we didn't find an active one
            if not active_stack_candidates and change_set_type == ChangeSetType.CREATE:
                stack = Stack(
                    account_id=context.account_id,
                    region_name=context.region,
                    request_payload=request,
                    initial_status=StackStatus.REVIEW_IN_PROGRESS,
                )
                state.stacks_v2[stack.stack_id] = stack
            else:
                if not active_stack_candidates:
                    raise ValidationError(f"Stack '{stack_name}' does not exist.")
                stack = active_stack_candidates[0]
                # propagate capabilities from create change set request
                stack.capabilities = request.get("Capabilities") or []

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

        # TODO: reconsider the way parameters are modelled in the update graph process.
        #  The options might be reduce to using the current style, or passing the extra information
        #  as a metadata object. The choice should be made considering when the extra information
        #  is needed for the update graph building, or only looked up in downstream tasks (metadata).
        request_parameters = request.get("Parameters", [])
        # TODO: handle parameter defaults and resolution
        after_parameters = self._extract_after_parameters(request_parameters, before_parameters)

        # TODO: update this logic to always pass the clean template object if one exists. The
        #  current issue with relaying on stack.template_original is that this appears to have
        #  its parameters and conditions populated.
        before_template = None
        if change_set_type == ChangeSetType.UPDATE:
            before_template = stack.template
        after_template = structured_template

        previous_update_model = None
        try:
            # FIXME: 'change_set_id' for 'stack' objects is dynamically attributed
            if previous_change_set := find_change_set_v2(state, stack.change_set_id):
                previous_update_model = previous_change_set.update_model
        except Exception:
            # No change set available on this stack.
            pass

        # create change set for the stack and apply changes
        change_set = ChangeSet(
            stack,
            request,
            template=after_template,
            template_body=template_body,
        )
        self._setup_change_set_model(
            change_set=change_set,
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
            previous_update_model=previous_update_model,
        )
        if change_set.status == ChangeSetStatus.FAILED:
            change_set.set_execution_status(ExecutionStatus.UNAVAILABLE)
        else:
            if not change_set.has_changes():
                change_set.set_change_set_status(ChangeSetStatus.FAILED)
                change_set.set_execution_status(ExecutionStatus.UNAVAILABLE)
                change_set.status_reason = "The submitted information didn't contain changes. Submit different information to create a change set."
            else:
                if stack.status not in [StackStatus.CREATE_COMPLETE, StackStatus.UPDATE_COMPLETE]:
                    stack.set_stack_status(StackStatus.REVIEW_IN_PROGRESS, "User Initiated")

                change_set.set_change_set_status(ChangeSetStatus.CREATE_COMPLETE)

        stack.change_set_ids.append(change_set.change_set_id)
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
        state = get_cloudformation_store(context.account_id, context.region)

        change_set = find_change_set_v2(state, change_set_name, stack_name)
        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")

        if change_set.execution_status != ExecutionStatus.AVAILABLE:
            LOG.debug("Change set %s not in execution status 'AVAILABLE'", change_set_name)
            raise InvalidChangeSetStatusException(
                f"ChangeSet [{change_set.change_set_id}] cannot be executed in its current status of [{change_set.status}]"
            )
        # LOG.debug(
        #     'Executing change set "%s" for stack "%s" with %s resources ...',
        #     change_set_name,
        #     stack_name,
        #     len(change_set.template_resources),
        # )
        if not change_set.update_model:
            raise RuntimeError("Programming error: no update graph found for change set")

        change_set.set_execution_status(ExecutionStatus.EXECUTE_IN_PROGRESS)
        # propagate the tags as this is done during execution
        change_set.stack.tags = change_set.tags
        change_set.stack.set_stack_status(
            StackStatus.UPDATE_IN_PROGRESS
            if change_set.change_set_type == ChangeSetType.UPDATE
            else StackStatus.CREATE_IN_PROGRESS
        )

        change_set_executor = ChangeSetModelExecutor(
            change_set,
        )

        def _run(*args):
            # TODO: should this be cleared before or after execution?
            change_set.stack.status_reason = None
            result = change_set_executor.execute()
            change_set.stack.resolved_parameters = change_set.resolved_parameters
            change_set.stack.resolved_resources = result.resources
            if not result.failure_message:
                new_stack_status = StackStatus.UPDATE_COMPLETE
                if change_set.change_set_type == ChangeSetType.CREATE:
                    new_stack_status = StackStatus.CREATE_COMPLETE
                change_set.stack.set_stack_status(new_stack_status)
                change_set.set_execution_status(ExecutionStatus.EXECUTE_COMPLETE)
                change_set.stack.resolved_outputs = result.outputs

                change_set.stack.resolved_exports = {}
                for output in result.outputs:
                    if export_name := output.get("ExportName"):
                        change_set.stack.resolved_exports[export_name] = output["OutputValue"]

                change_set.stack.change_set_id = change_set.change_set_id
                change_set.stack.change_set_ids.append(change_set.change_set_id)

                # if the deployment succeeded, update the stack's template representation to that
                # which was just deployed
                change_set.stack.template = change_set.template
                change_set.stack.description = change_set.template.get("Description")
                change_set.stack.processed_template = change_set.processed_template
                change_set.stack.template_body = change_set.template_body
            else:
                LOG.error(
                    "Execute change set failed: %s",
                    result.failure_message,
                    exc_info=LOG.isEnabledFor(logging.DEBUG) and config.CFN_VERBOSE_ERRORS,
                )
                # stack status is taken care of in the executor
                change_set.set_execution_status(ExecutionStatus.EXECUTE_FAILED)
                change_set.stack.deletion_time = datetime.now(tz=UTC)

        start_worker_thread(_run)

        return ExecuteChangeSetOutput()

    @staticmethod
    def _render_resolved_parameters(
        resolved_parameters: dict[str, EngineParameter],
    ) -> list[Parameter]:
        result = []
        for name, resolved_parameter in resolved_parameters.items():
            parameter = Parameter(
                ParameterKey=name,
                ParameterValue=resolved_parameter.get("given_value")
                or resolved_parameter.get("default_value"),
            )
            if resolved_value := resolved_parameter.get("resolved_value"):
                parameter["ResolvedValue"] = resolved_value

            # TODO :what happens to the resolved value?
            if resolved_parameter.get("no_echo", False):
                parameter["ParameterValue"] = "****"
            result.append(parameter)

        return result

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
        change_set = find_change_set_v2(state, change_set_name, stack_name)

        if not change_set:
            raise ChangeSetNotFoundException(f"ChangeSet [{change_set_name}] does not exist")

        # if the change set failed to create, then we can return a blank response
        if change_set.status == ChangeSetStatus.FAILED:
            return DescribeChangeSetOutput(
                Status=change_set.status,
                ChangeSetId=change_set.change_set_id,
                ChangeSetName=change_set.change_set_name,
                ExecutionStatus=change_set.execution_status,
                RollbackConfiguration=RollbackConfiguration(),
                StackId=change_set.stack.stack_id,
                StackName=change_set.stack.stack_name,
                CreationTime=change_set.creation_time,
                Changes=[],
                Capabilities=change_set.stack.capabilities,
                StatusReason=change_set.status_reason,
                Description=change_set.description,
                # TODO: static information
                IncludeNestedStacks=False,
                NotificationARNs=[],
                Tags=change_set.tags or None,
            )

        # TODO: The ChangeSetModelDescriber currently matches AWS behavior by listing
        #       resource changes in the order they appear in the template. However, when
        #       a resource change is triggered indirectly (e.g., via Ref or GetAtt), the
        #       dependency's change appears first in the list.
        #       Snapshot tests using the `capture_update_process` fixture rely on a
        #       normalizer to account for this ordering. This should be removed in the
        #       future by enforcing a consistently correct change ordering at the source.
        change_set_describer = ChangeSetModelDescriber(
            change_set=change_set, include_property_values=include_property_values
        )
        changes: Changes = change_set_describer.get_changes()

        result = DescribeChangeSetOutput(
            Status=change_set.status,
            ChangeSetId=change_set.change_set_id,
            ChangeSetName=change_set.change_set_name,
            ExecutionStatus=change_set.execution_status,
            RollbackConfiguration=RollbackConfiguration(),
            StackId=change_set.stack.stack_id,
            StackName=change_set.stack.stack_name,
            CreationTime=change_set.creation_time,
            Changes=changes,
            Capabilities=change_set.stack.capabilities,
            StatusReason=change_set.status_reason,
            Description=change_set.description,
            # TODO: static information
            IncludeNestedStacks=False,
            NotificationARNs=[],
            Tags=change_set.tags or None,
        )
        if change_set.resolved_parameters:
            result["Parameters"] = self._render_resolved_parameters(change_set.resolved_parameters)
        return result

    @handler("DeleteChangeSet")
    def delete_change_set(
        self,
        context: RequestContext,
        change_set_name: ChangeSetNameOrId,
        stack_name: StackNameOrId = None,
        **kwargs,
    ) -> DeleteChangeSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        change_set = find_change_set_v2(state, change_set_name, stack_name)
        if not change_set:
            return DeleteChangeSetOutput()

        change_set.stack.change_set_ids.remove(change_set.change_set_id)
        state.change_sets.pop(change_set.change_set_id)

        return DeleteChangeSetOutput()

    @handler("CreateStack", expand=False)
    def create_stack(self, context: RequestContext, request: CreateStackInput) -> CreateStackOutput:
        try:
            stack_name = request["StackName"]
        except KeyError:
            # TODO: proper exception
            raise ValidationError("StackName must be specified")

        state = get_cloudformation_store(context.account_id, context.region)

        active_stack_candidates = [
            stack
            for stack in state.stacks_v2.values()
            if stack.stack_name == stack_name and stack.status not in [StackStatus.DELETE_COMPLETE]
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

        # TODO: copied from create_change_set, consider unifying
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

        if len(template_body) > 51200 and not template_url:
            raise ValidationError(
                f"1 validation error detected: Value '{template_body}' at 'templateBody' "
                "failed to satisfy constraint: Member must have length less than or equal to 51200"
            )

        if "CAPABILITY_AUTO_EXPAND" not in request.get("Capabilities", []) and (
            "Transform" in structured_template.keys() or "Fn::Transform" in template_body
        ):
            raise InsufficientCapabilitiesException(
                "Requires capabilities : [CAPABILITY_AUTO_EXPAND]"
            )

        stack = Stack(
            account_id=context.account_id,
            region_name=context.region,
            request_payload=request,
            tags=request.get("Tags"),
        )
        # TODO: what is the correct initial status?
        state.stacks_v2[stack.stack_id] = stack

        # TODO: reconsider the way parameters are modelled in the update graph process.
        #  The options might be reduce to using the current style, or passing the extra information
        #  as a metadata object. The choice should be made considering when the extra information
        #  is needed for the update graph building, or only looked up in downstream tasks (metadata).
        request_parameters = request.get("Parameters", [])
        # TODO: handle parameter defaults and resolution
        after_parameters = self._extract_after_parameters(request_parameters)
        after_template = structured_template

        # Create internal change set to execute
        change_set = ChangeSet(
            stack,
            {"ChangeSetName": f"cs-{stack_name}-create", "ChangeSetType": ChangeSetType.CREATE},
            template=after_template,
            template_body=template_body,
        )
        self._setup_change_set_model(
            change_set=change_set,
            before_template=None,
            after_template=after_template,
            before_parameters=None,
            after_parameters=after_parameters,
            previous_update_model=None,
        )
        if change_set.status == ChangeSetStatus.FAILED:
            return CreateStackOutput(StackId=stack.stack_id)

        stack.processed_template = change_set.processed_template

        # deployment process
        stack.set_stack_status(StackStatus.CREATE_IN_PROGRESS)
        change_set_executor = ChangeSetModelExecutor(change_set)

        def _run(*args):
            try:
                result = change_set_executor.execute()
                stack.resolved_resources = result.resources
                stack.resolved_outputs = result.outputs
                if all(
                    resource["ResourceStatus"] == ResourceStatus.CREATE_COMPLETE
                    for resource in stack.resolved_resources.values()
                ):
                    stack.set_stack_status(StackStatus.CREATE_COMPLETE)
                else:
                    stack.set_stack_status(StackStatus.CREATE_FAILED)

                # if the deployment succeeded, update the stack's template representation to that
                # which was just deployed
                stack.template = change_set.template
                stack.template_body = change_set.template_body
                stack.processed_template = change_set.processed_template
                stack.resolved_parameters = change_set.resolved_parameters
                stack.resolved_exports = {}
                for output in result.outputs:
                    if export_name := output.get("ExportName"):
                        stack.resolved_exports[export_name] = output["OutputValue"]
            except Exception as e:
                LOG.error(
                    "Create Stack set failed: %s",
                    e,
                    exc_info=LOG.isEnabledFor(logging.WARNING) and config.CFN_VERBOSE_ERRORS,
                )
                stack.set_stack_status(StackStatus.CREATE_FAILED)

        start_worker_thread(_run)

        return CreateStackOutput(StackId=stack.stack_id)

    @handler("CreateStackSet", expand=False)
    def create_stack_set(
        self, context: RequestContext, request: CreateStackSetInput
    ) -> CreateStackSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        stack_set = StackSet(context.account_id, context.region, request)
        state.stack_sets_v2[stack_set.stack_set_id] = stack_set

        return CreateStackSetOutput(StackSetId=stack_set.stack_set_id)

    @handler("DescribeStacks")
    def describe_stacks(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeStacksOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        if stack_name:
            stack = find_stack_v2(state, stack_name)
            if not stack:
                raise ValidationError(f"Stack with id {stack_name} does not exist")
            stacks = [stack]
        else:
            stacks = state.stacks_v2.values()

        describe_stack_output: list[ApiStack] = []
        for stack in stacks:
            describe_stack_output.append(self._describe_stack(stack))

        return DescribeStacksOutput(Stacks=describe_stack_output)

    def _describe_stack(self, stack: Stack) -> ApiStack:
        stack_description = ApiStack(
            Description=stack.description,
            CreationTime=stack.creation_time,
            StackId=stack.stack_id,
            StackName=stack.stack_name,
            StackStatus=stack.status,
            StackStatusReason=stack.status_reason,
            # fake values
            DisableRollback=False,
            DriftInformation=StackDriftInformation(StackDriftStatus=StackDriftStatus.NOT_CHECKED),
            EnableTerminationProtection=stack.enable_termination_protection,
            RollbackConfiguration=RollbackConfiguration(),
            Tags=stack.tags,
            NotificationARNs=[],
        )
        if stack.status != StackStatus.REVIEW_IN_PROGRESS:
            # TODO: actually track updated time
            stack_description["LastUpdatedTime"] = stack.creation_time
        if stack.deletion_time:
            stack_description["DeletionTime"] = stack.deletion_time
        if stack.capabilities:
            stack_description["Capabilities"] = stack.capabilities
        # TODO: confirm the logic for this
        if change_set_id := stack.change_set_id:
            stack_description["ChangeSetId"] = change_set_id

        if stack.resolved_parameters:
            stack_description["Parameters"] = self._render_resolved_parameters(
                stack.resolved_parameters
            )

        if stack.resolved_outputs:
            stack_description["Outputs"] = stack.resolved_outputs

        return stack_description

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
            self._describe_stack(s)
            for s in state.stacks_v2.values()
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

    @handler("ListStackResources")
    def list_stack_resources(
        self, context: RequestContext, stack_name: StackName, next_token: NextToken = None, **kwargs
    ) -> ListStackResourcesOutput:
        result = self.describe_stack_resources(context, stack_name)

        resources = []
        for resource in result.get("StackResources", []):
            resources.append(
                StackResourceSummary(
                    LogicalResourceId=resource["LogicalResourceId"],
                    PhysicalResourceId=resource["PhysicalResourceId"],
                    ResourceType=resource["ResourceType"],
                    LastUpdatedTimestamp=resource["Timestamp"],
                    ResourceStatus=resource["ResourceStatus"],
                    ResourceStatusReason=resource.get("ResourceStatusReason"),
                    DriftInformation=resource.get("DriftInformation"),
                    ModuleInfo=resource.get("ModuleInfo"),
                )
            )

        return ListStackResourcesOutput(StackResourceSummaries=resources)

    @handler("DescribeStackResource")
    def describe_stack_resource(
        self,
        context: RequestContext,
        stack_name: StackName,
        logical_resource_id: LogicalResourceId,
        **kwargs,
    ) -> DescribeStackResourceOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        stack = find_stack_v2(state, stack_name)
        if not stack:
            raise StackNotFoundError(
                stack_name, message_override=f"Stack '{stack_name}' does not exist"
            )

        try:
            resource = stack.resolved_resources[logical_resource_id]
        except KeyError:
            raise ValidationError(
                f"Resource {logical_resource_id} does not exist for stack {stack_name}"
            )

        resource_detail = StackResourceDetail(
            StackName=stack.stack_name,
            StackId=stack.stack_id,
            LogicalResourceId=logical_resource_id,
            PhysicalResourceId=resource["PhysicalResourceId"],
            ResourceType=resource["Type"],
            LastUpdatedTimestamp=resource["LastUpdatedTimestamp"],
            ResourceStatus=resource["ResourceStatus"],
            DriftInformation={"StackResourceDriftStatus": "NOT_CHECKED"},
        )
        return DescribeStackResourceOutput(StackResourceDetail=resource_detail)

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
        state = get_cloudformation_store(context.account_id, context.region)
        stack = find_stack_v2(state, stack_name)
        if not stack:
            raise StackNotFoundError(stack_name)
        # TODO: filter stack by PhysicalResourceId!
        statuses = []
        for resource_id, resource_status in stack.resource_states.items():
            if resource_id == logical_resource_id or logical_resource_id is None:
                status = copy.deepcopy(resource_status)
                status.setdefault("DriftInformation", {"StackResourceDriftStatus": "NOT_CHECKED"})
                statuses.append(status)
        return DescribeStackResourcesOutput(StackResources=statuses)

    @handler("CreateStackInstances", expand=False)
    def create_stack_instances(
        self,
        context: RequestContext,
        request: CreateStackInstancesInput,
    ) -> CreateStackInstancesOutput:
        state = get_cloudformation_store(context.account_id, context.region)

        stack_set_name = request["StackSetName"]
        stack_set = find_stack_set_v2(state, stack_set_name)
        if not stack_set:
            raise StackSetNotFoundError(stack_set_name)

        op_id = request.get("OperationId") or short_uid()
        accounts = request["Accounts"]
        regions = request["Regions"]

        stacks_to_await = []
        for account in accounts:
            for region in regions:
                # deploy new stack
                LOG.debug(
                    'Deploying instance for stack set "%s" in account: %s region %s',
                    stack_set_name,
                    account,
                    region,
                )
                cf_client = connect_to(aws_access_key_id=account, region_name=region).cloudformation
                if stack_set.template_body:
                    kwargs = {
                        "TemplateBody": stack_set.template_body,
                    }
                elif stack_set.template_url:
                    kwargs = {
                        "TemplateURL": stack_set.template_url,
                    }
                else:
                    # TODO: wording
                    raise ValueError("Neither StackSet Template URL nor TemplateBody provided")
                stack_name = f"sset-{stack_set_name}-{account}-{region}"

                # skip creation of existing stacks
                if find_stack_v2(state, stack_name):
                    continue

                result = cf_client.create_stack(StackName=stack_name, **kwargs)
                # store stack instance
                stack_instance = StackInstance(
                    account_id=account,
                    region_name=region,
                    stack_set_id=stack_set.stack_set_id,
                    operation_id=op_id,
                    stack_id=result["StackId"],
                )
                stack_set.stack_instances.append(stack_instance)

                stacks_to_await.append((stack_name, account, region))

        # wait for completion of stack
        for stack_name, account_id, region_name in stacks_to_await:
            client = connect_to(
                aws_access_key_id=account_id, region_name=region_name
            ).cloudformation
            client.get_waiter("stack_create_complete").wait(StackName=stack_name)

        # record operation
        operation = StackSetOperation(
            OperationId=op_id,
            StackSetId=stack_set.stack_set_id,
            Action=StackSetOperationAction.CREATE,
            Status=StackSetOperationStatus.SUCCEEDED,
        )
        stack_set.operations[op_id] = operation

        return CreateStackInstancesOutput(OperationId=op_id)

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
        stack_set = find_stack_set_v2(state, stack_set_name)
        if not stack_set:
            raise StackSetNotFoundError(stack_set_name)

        result = stack_set.operations.get(operation_id)
        if not result:
            LOG.debug(
                'Unable to find operation ID "%s" for stack set "%s" in list: %s',
                operation_id,
                stack_set_name,
                list(stack_set.operations.keys()),
            )
            # TODO: proper exception
            raise ValueError(
                f'Unable to find operation ID "{operation_id}" for stack set "{stack_set_name}"'
            )

        return DescribeStackSetOperationOutput(StackSetOperation=result)

    @handler("DeleteStackInstances", expand=False)
    def delete_stack_instances(
        self,
        context: RequestContext,
        request: DeleteStackInstancesInput,
    ) -> DeleteStackInstancesOutput:
        state = get_cloudformation_store(context.account_id, context.region)

        stack_set_name = request["StackSetName"]
        stack_set = find_stack_set_v2(state, stack_set_name)
        if not stack_set:
            raise StackSetNotFoundError(stack_set_name)

        op_id = request.get("OperationId") or short_uid()

        accounts = request["Accounts"]
        regions = request["Regions"]

        operations_to_await = []
        for account in accounts:
            for region in regions:
                cf_client = connect_to(aws_access_key_id=account, region_name=region).cloudformation
                instance = find_stack_instance(stack_set, account, region)

                # TODO: check parity with AWS
                # TODO: delete stack instance?
                if not instance:
                    continue

                cf_client.delete_stack(StackName=instance.stack_id)
                operations_to_await.append(instance)

        for instance in operations_to_await:
            cf_client = connect_to(
                aws_access_key_id=instance.account_id, region_name=instance.region_name
            ).cloudformation
            cf_client.get_waiter("stack_delete_complete").wait(StackName=instance.stack_id)
            stack_set.stack_instances.remove(instance)

        # record operation
        operation = StackSetOperation(
            OperationId=op_id,
            StackSetId=stack_set.stack_set_id,
            Action=StackSetOperationAction.DELETE,
            Status=StackSetOperationStatus.SUCCEEDED,
        )
        stack_set.operations[op_id] = operation

        return DeleteStackInstancesOutput(OperationId=op_id)

    @handler("DeleteStackSet")
    def delete_stack_set(
        self,
        context: RequestContext,
        stack_set_name: StackSetName,
        call_as: CallAs = None,
        **kwargs,
    ) -> DeleteStackSetOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        stack_set = find_stack_set_v2(state, stack_set_name)
        if not stack_set:
            # operation is idempotent
            return DeleteStackSetOutput()

        # clean up any left-over instances
        operations_to_await = []
        for instance in stack_set.stack_instances:
            cf_client = connect_to(
                aws_access_key_id=instance.account_id, region_name=instance.region_name
            ).cloudformation
            cf_client.delete_stack(StackName=instance.stack_id)
            operations_to_await.append(instance)

        for instance in operations_to_await:
            cf_client = connect_to(
                aws_access_key_id=instance.account_id, region_name=instance.region_name
            ).cloudformation
            cf_client.get_waiter("stack_delete_complete").wait(StackName=instance.stack_id)
            stack_set.stack_instances.remove(instance)

        state.stack_sets_v2.pop(stack_set.stack_set_id)

        return DeleteStackSetOutput()

    @handler("DescribeStackEvents")
    def describe_stack_events(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        next_token: NextToken = None,
        **kwargs,
    ) -> DescribeStackEventsOutput:
        if not stack_name:
            raise ValidationError(
                "1 validation error detected: Value null at 'stackName' failed to satisfy constraint: Member must not be null"
            )
        state = get_cloudformation_store(context.account_id, context.region)
        stack = find_stack_v2(state, stack_name)
        if not stack:
            raise StackNotFoundError(stack_name)
        return DescribeStackEventsOutput(StackEvents=stack.events)

    @handler("GetTemplate")
    def get_template(
        self,
        context: RequestContext,
        stack_name: StackName = None,
        change_set_name: ChangeSetNameOrId = None,
        template_stage: TemplateStage = None,
        **kwargs,
    ) -> GetTemplateOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        if change_set_name:
            change_set = find_change_set_v2(state, change_set_name, stack_name=stack_name)
            stack = change_set.stack
        elif stack_name:
            stack = find_stack_v2(state, stack_name)
        else:
            raise StackNotFoundError(stack_name)

        if template_stage == TemplateStage.Processed and "Transform" in stack.template_body:
            template_body = json.dumps(stack.processed_template)
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
        state = get_cloudformation_store(context.account_id, context.region)
        stack_name = request.get("StackName")

        if stack_name:
            stack = find_stack_v2(state, stack_name)
            if not stack:
                raise StackNotFoundError(stack_name)
            template = stack.template
        else:
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
            template = template_preparer.parse_template(template_body)

        id_summaries = defaultdict(list)
        for resource_id, resource in template["Resources"].items():
            res_type = resource["Type"]
            id_summaries[res_type].append(resource_id)

        summarized_parameters = []
        for parameter_id, parameter_body in template.get("Parameters", {}).items():
            summarized_parameters.append(
                {
                    "ParameterKey": parameter_id,
                    "DefaultValue": parameter_body.get("Default"),
                    "ParameterType": parameter_body["Type"],
                    "Description": parameter_body.get("Description"),
                }
            )
        result = GetTemplateSummaryOutput(
            Parameters=summarized_parameters,
            Metadata=template.get("Metadata"),
            ResourceIdentifierSummaries=[
                {"ResourceType": key, "LogicalResourceIds": values}
                for key, values in id_summaries.items()
            ],
            ResourceTypes=list(id_summaries.keys()),
            Version=template.get("AWSTemplateFormatVersion", "2010-09-09"),
        )

        return result

    @handler("UpdateTerminationProtection")
    def update_termination_protection(
        self,
        context: RequestContext,
        enable_termination_protection: EnableTerminationProtection,
        stack_name: StackNameOrId,
        **kwargs,
    ) -> UpdateTerminationProtectionOutput:
        state = get_cloudformation_store(context.account_id, context.region)
        stack = find_stack_v2(state, stack_name)
        if not stack:
            raise StackNotFoundError(stack_name)

        stack.enable_termination_protection = enable_termination_protection
        return UpdateTerminationProtectionOutput(StackId=stack.stack_id)

    @handler("UpdateStack", expand=False)
    def update_stack(
        self,
        context: RequestContext,
        request: UpdateStackInput,
    ) -> UpdateStackOutput:
        try:
            stack_name = request["StackName"]
        except KeyError:
            # TODO: proper exception
            raise ValidationError("StackName must be specified")
        state = get_cloudformation_store(context.account_id, context.region)
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

        if "CAPABILITY_AUTO_EXPAND" not in request.get("Capabilities", []) and (
            "Transform" in structured_template.keys() or "Fn::Transform" in template_body
        ):
            raise InsufficientCapabilitiesException(
                "Requires capabilities : [CAPABILITY_AUTO_EXPAND]"
            )

        # this is intentionally not in a util yet. Let's first see how the different operations deal with these before generalizing
        # handle ARN stack_name here (not valid for initial CREATE, since stack doesn't exist yet)
        stack: Stack
        if is_stack_arn(stack_name):
            stack = state.stacks_v2.get(stack_name)
            if not stack:
                raise ValidationError(f"Stack '{stack_name}' does not exist.")

        else:
            # stack name specified, so fetch the stack by name
            stack_candidates: list[Stack] = [
                s for stack_arn, s in state.stacks_v2.items() if s.stack_name == stack_name
            ]
            active_stack_candidates = [
                s for s in stack_candidates if self._stack_status_is_active(s.status)
            ]

            if not active_stack_candidates:
                raise ValidationError(f"Stack '{stack_name}' does not exist.")
            elif len(active_stack_candidates) > 1:
                raise RuntimeError("Multiple stacks matched, update matching logic")
            stack = active_stack_candidates[0]

        # TODO: proper status modeling
        before_parameters = stack.resolved_parameters
        # TODO: reconsider the way parameters are modelled in the update graph process.
        #  The options might be reduce to using the current style, or passing the extra information
        #  as a metadata object. The choice should be made considering when the extra information
        #  is needed for the update graph building, or only looked up in downstream tasks (metadata).
        request_parameters = request.get("Parameters", [])
        # TODO: handle parameter defaults and resolution
        after_parameters = self._extract_after_parameters(request_parameters, before_parameters)

        before_template = stack.template
        after_template = structured_template

        previous_update_model = None
        if stack.change_set_id:
            if previous_change_set := find_change_set_v2(state, stack.change_set_id):
                previous_update_model = previous_change_set.update_model

        change_set = ChangeSet(
            stack,
            {"ChangeSetName": f"cs-{stack_name}-create", "ChangeSetType": ChangeSetType.CREATE},
            template_body=template_body,
            template=after_template,
        )
        self._setup_change_set_model(
            change_set=change_set,
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
            previous_update_model=previous_update_model,
        )

        # TODO: some changes are only detectable at runtime; consider using
        #       the ChangeSetModelDescriber, or a new custom visitors, to
        #       pick-up on runtime changes.
        if not change_set.has_changes():
            raise ValidationError("No updates are to be performed.")

        stack.set_stack_status(StackStatus.UPDATE_IN_PROGRESS)
        change_set_executor = ChangeSetModelExecutor(change_set)

        def _run(*args):
            try:
                result = change_set_executor.execute()
                stack.set_stack_status(StackStatus.UPDATE_COMPLETE)
                stack.resolved_resources = result.resources
                stack.resolved_outputs = result.outputs
                # if the deployment succeeded, update the stack's template representation to that
                # which was just deployed
                stack.template = change_set.template
                stack.template_body = change_set.template_body
                stack.resolved_parameters = change_set.resolved_parameters
                stack.resolved_exports = {}
                for output in result.outputs:
                    if export_name := output.get("ExportName"):
                        stack.resolved_exports[export_name] = output["OutputValue"]
            except Exception as e:
                LOG.error(
                    "Update Stack failed: %s",
                    e,
                    exc_info=LOG.isEnabledFor(logging.WARNING) and config.CFN_VERBOSE_ERRORS,
                )
                stack.set_stack_status(StackStatus.UPDATE_FAILED)

        start_worker_thread(_run)

        return UpdateStackOutput(StackId=stack.stack_id)

    @staticmethod
    def _extract_after_parameters(
        request_parameters, before_parameters: dict[str, str] | None = None
    ) -> dict[str, str]:
        before_parameters = before_parameters or {}
        after_parameters = {}
        for parameter in request_parameters:
            key = parameter["ParameterKey"]
            if parameter.get("UsePreviousValue", False):
                # todo: what if the parameter does not exist in the before parameters
                before = before_parameters[key]
                after_parameters[key] = (
                    before.get("resolved_value")
                    or before.get("given_value")
                    or before.get("default_value")
                )
                continue

            if "ParameterValue" in parameter:
                after_parameters[key] = parameter["ParameterValue"]
                continue
        return after_parameters

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
        state = get_cloudformation_store(context.account_id, context.region)
        stack = find_stack_v2(state, stack_name)
        if not stack:
            # aws will silently ignore invalid stack names - we should do the same
            return

        # shortcut for stacks which have no deployed resources i.e. where a change set was
        # created, but never executed
        if stack.status == StackStatus.REVIEW_IN_PROGRESS and not stack.resolved_resources:
            stack.set_stack_status(StackStatus.DELETE_COMPLETE)
            stack.deletion_time = datetime.now(tz=UTC)
            return

        stack.set_stack_status(StackStatus.DELETE_IN_PROGRESS)

        # create a dummy change set
        change_set = ChangeSet(
            stack, {"ChangeSetName": f"delete-stack_{stack.stack_name}"}, template_body=""
        )  # noqa
        self._setup_change_set_model(
            change_set=change_set,
            before_template=stack.processed_template,
            after_template=None,
            before_parameters=stack.resolved_parameters,
            after_parameters=None,
        )

        change_set_executor = ChangeSetModelExecutor(change_set)

        def _run(*args):
            try:
                change_set_executor.execute()
                stack.set_stack_status(StackStatus.DELETE_COMPLETE)
                stack.deletion_time = datetime.now(tz=UTC)
            except Exception as e:
                LOG.warning(
                    "Failed to delete stack '%s': %s",
                    stack.stack_name,
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG) and config.CFN_VERBOSE_ERRORS,
                )
                stack.set_stack_status(StackStatus.DELETE_FAILED)

        start_worker_thread(_run)

    @handler("ListExports")
    def list_exports(
        self, context: RequestContext, next_token: NextToken = None, **kwargs
    ) -> ListExportsOutput:
        store = get_cloudformation_store(account_id=context.account_id, region_name=context.region)
        return ListExportsOutput(Exports=store.exports_v2.values())
