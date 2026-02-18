from datetime import UTC, datetime
from typing import NotRequired, TypedDict

from localstack import config
from localstack.aws.api.cloudformation import (
    Capability,
    ChangeSetStatus,
    ChangeSetType,
    CreateChangeSetInput,
    CreateStackInput,
    CreateStackSetInput,
    ExecutionStatus,
    Output,
    ResourceStatus,
    StackEvent,
    StackInstanceComprehensiveStatus,
    StackInstanceDetailedStatus,
    StackInstanceStatus,
    StackResource,
    StackSetOperation,
    StackStatus,
    StackStatusReason,
    Tag,
)
from localstack.aws.api.cloudformation import (
    Parameter as ApiParameter,
)
from localstack.services.cloudformation.engine.entities import (
    StackIdentifierV2,
)
from localstack.services.cloudformation.engine.transformers import FailedTransformationException
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    ChangeType,
    UpdateModel,
)
from localstack.services.cloudformation.engine.v2.change_set_model_transform import (
    ChangeSetModelTransform,
)
from localstack.services.cloudformation.engine.v2.change_set_model_validator import (
    ChangeSetModelValidator,
)
from localstack.services.cloudformation.engine.v2.change_set_resource_support_checker import (
    ChangeSetResourceSupportChecker,
)
from localstack.services.cloudformation.engine.v2.resolving import resolve_parameters
from localstack.services.cloudformation.v2.types import EngineParameter, ResolvedResource
from localstack.utils.aws import arns
from localstack.utils.strings import long_uid, short_uid


class Stack:
    stack_name: str
    description: str | None
    parameters: list[ApiParameter]
    change_set_id: str | None
    change_set_ids: set[str]
    status: StackStatus
    status_reason: StackStatusReason | None
    stack_id: str
    creation_time: datetime
    deletion_time: datetime | None
    events: list[StackEvent]
    capabilities: list[Capability]
    enable_termination_protection: bool
    template: dict | None
    processed_template: dict | None
    template_body: str | None
    tags: list[Tag]

    # state after deploy
    resolved_parameters: dict[str, EngineParameter]
    resolved_resources: dict[str, ResolvedResource]
    resolved_outputs: list[Output]
    resource_states: dict[str, StackResource]
    resolved_exports: dict[str, str]

    def __init__(
        self,
        account_id: str,
        region_name: str,
        request_payload: CreateChangeSetInput | CreateStackInput,
        initial_status: StackStatus = StackStatus.CREATE_IN_PROGRESS,
        tags: list[Tag] | None = None,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.status = initial_status
        self.status_reason = None
        self.change_set_ids = set()
        self.creation_time = datetime.now(tz=UTC)
        self.deletion_time = None
        self.change_set_id = None
        self.enable_termination_protection = False
        self.template = None
        self.processed_template = None
        self.template_body = None
        self.tags = tags or []

        self.stack_name = request_payload["StackName"]
        self.parameters = request_payload.get("Parameters", [])
        self.stack_id = arns.cloudformation_stack_arn(
            self.stack_name,
            stack_id=StackIdentifierV2(
                account_id=self.account_id, region=self.region_name, stack_name=self.stack_name
            ).generate(tags=request_payload.get("Tags")),
            account_id=self.account_id,
            region_name=self.region_name,
        )
        self.capabilities = request_payload.get("Capabilities", []) or []

        # TODO: only kept for v1 compatibility
        self.request_payload = request_payload

        # state after deploy
        self.resolved_parameters = {}
        self.resolved_resources = {}
        self.resolved_outputs = []
        self.resource_states = {}
        self.events = []
        self.resolved_exports = {}
        self.description = None

    def set_stack_status(self, status: StackStatus, reason: StackStatusReason | None = None):
        self.status = status
        if reason:
            self.status_reason = reason

        self._store_event(
            resource_id=self.stack_name,
            resource_type="AWS::CloudFormation::Stack",
            physical_resource_id=self.stack_id,
            status=status,
            status_reason=reason,
        )

    def set_resource_status(
        self,
        *,
        logical_resource_id: str,
        physical_resource_id: str | None,
        resource_type: str,
        status: ResourceStatus,
        resource_status_reason: str | None = None,
    ):
        resource_description = StackResource(
            StackName=self.stack_name,
            StackId=self.stack_id,
            LogicalResourceId=logical_resource_id,
            PhysicalResourceId=physical_resource_id,
            ResourceType=resource_type,
            Timestamp=datetime.now(tz=UTC),
            ResourceStatus=status,
            ResourceStatusReason=resource_status_reason,
        )

        if not resource_status_reason:
            resource_description.pop("ResourceStatusReason")

        if status == ResourceStatus.DELETE_COMPLETE:
            self.resource_states.pop(logical_resource_id)
        else:
            self.resource_states[logical_resource_id] = resource_description

        self._store_event(
            resource_id=logical_resource_id,
            resource_type=resource_type,
            physical_resource_id=physical_resource_id,
            status=status,
            status_reason=resource_status_reason,
        )

    def _store_event(
        self,
        resource_id: str = None,
        resource_type: str | None = "",
        physical_resource_id: str = None,
        status: StackStatus | ResourceStatus = "",
        status_reason: str = "",
    ):
        event = StackEvent(
            EventId=long_uid(),
            Timestamp=datetime.now(tz=UTC),
            StackId=self.stack_id,
            StackName=self.stack_name,
            LogicalResourceId=resource_id,
            PhysicalResourceId=physical_resource_id,
            ResourceStatus=status,
            ResourceType=resource_type,
        )

        if status_reason:
            event["ResourceStatusReason"] = status_reason

        self.events.insert(0, event)

    def is_active(self) -> bool:
        return self.status != StackStatus.DELETE_COMPLETE


class ChangeSetRequestPayload(TypedDict, total=False):
    ChangeSetName: str
    ChangeSetType: NotRequired[ChangeSetType]


class ChangeSet:
    change_set_name: str
    change_set_id: str
    change_set_type: ChangeSetType
    status: ChangeSetStatus
    status_reason: str | None
    execution_status: ExecutionStatus
    creation_time: datetime
    processed_template: dict | None
    resolved_parameters: dict[str, EngineParameter]
    description: str | None
    tags: list[Tag]

    def __init__(
        self,
        stack: Stack,
        request_payload: ChangeSetRequestPayload,
        template_body: str,
        template: dict | None = None,
    ):
        self.stack = stack
        self.template_body = template_body
        self.template = template
        self.status = ChangeSetStatus.CREATE_IN_PROGRESS
        self.status_reason = None
        self.execution_status = ExecutionStatus.AVAILABLE
        self.creation_time = datetime.now(tz=UTC)
        self.resolved_parameters = {}
        self.tags = request_payload.get("Tags") or []

        # non-persisted state
        self.update_model: UpdateModel | None = None

        self.change_set_name = request_payload["ChangeSetName"]
        self.change_set_type = request_payload.get("ChangeSetType", ChangeSetType.UPDATE)
        self.description = request_payload.get("Description")
        self.change_set_id = arns.cloudformation_change_set_arn(
            self.change_set_name,
            change_set_id=short_uid(),
            account_id=self.stack.account_id,
            region_name=self.stack.region_name,
        )
        self.processed_template = None

    def set_change_set_status(self, status: ChangeSetStatus):
        self.status = status

    def set_execution_status(self, execution_status: ExecutionStatus):
        self.execution_status = execution_status

    def has_changes(self) -> bool:
        if self.update_model is None:
            raise ValueError("update model has not been computed")
        return self.update_model.node_template.change_type != ChangeType.UNCHANGED

    @property
    def account_id(self) -> str:
        return self.stack.account_id

    @property
    def region_name(self) -> str:
        return self.stack.region_name

    def compute_update_model(
        self,
        before_template: dict | None,
        after_template: dict | None,
        before_parameters: dict | None,
        after_parameters: dict | None,
        previous_update_model: UpdateModel | None = None,
    ):
        resolved_parameters = None
        if after_parameters is not None:
            resolved_parameters = resolve_parameters(
                after_template,
                after_parameters,
                self.account_id,
                self.region_name,
                before_parameters,
            )

        self.resolved_parameters = resolved_parameters or {}

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
        self.update_model = raw_update_model

        # Apply global transforms.
        # TODO: skip this process iff both versions of the template don't specify transform blocks.
        change_set_model_transform = ChangeSetModelTransform(
            change_set=self,
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
            self.status = ChangeSetStatus.FAILED
            self.status_reason = e.message
            self.stack.set_stack_status(status=StackStatus.ROLLBACK_IN_PROGRESS, reason=e.message)
            self.stack.set_stack_status(status=StackStatus.CREATE_FAILED)
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
        self.update_model = update_model

        # perform validations
        validator = ChangeSetModelValidator(
            change_set=self,
        )
        validator.validate()

        # hacky
        if transform := raw_update_model.node_template.transform:
            if transform.global_transforms:
                # global transforms should always be considered "MODIFIED"
                update_model.node_template.change_type = ChangeType.MODIFIED
        self.processed_template = transformed_after_template

        if not config.CFN_IGNORE_UNSUPPORTED_RESOURCE_TYPES:
            support_visitor = ChangeSetResourceSupportChecker(change_set_type=self.change_set_type)
            support_visitor.visit(self.update_model.node_template)
            failure_messages = support_visitor.failure_messages
            if failure_messages:
                reason_suffix = ", ".join(failure_messages)
                status_reason = f"{ChangeSetResourceSupportChecker.TITLE_MESSAGE} {reason_suffix}"

                self.status_reason = status_reason
                self.set_change_set_status(ChangeSetStatus.FAILED)
                failure_transitions = {
                    ChangeSetType.CREATE: (
                        StackStatus.ROLLBACK_IN_PROGRESS,
                        StackStatus.CREATE_FAILED,
                    ),
                    ChangeSetType.UPDATE: (
                        StackStatus.UPDATE_ROLLBACK_IN_PROGRESS,
                        StackStatus.UPDATE_ROLLBACK_FAILED,
                    ),
                    ChangeSetType.IMPORT: (
                        StackStatus.IMPORT_ROLLBACK_IN_PROGRESS,
                        StackStatus.IMPORT_ROLLBACK_FAILED,
                    ),
                }
                transitions = failure_transitions.get(self.change_set_type)
                if transitions:
                    first_status, *remaining_statuses = transitions
                    self.stack.set_stack_status(first_status, status_reason)
                    for status in remaining_statuses:
                        self.stack.set_stack_status(status)
                return


class StackInstance:
    def __init__(
        self, account_id: str, region_name: str, stack_set_id: str, operation_id: str, stack_id: str
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.stack_set_id = stack_set_id
        self.operation_id = operation_id
        self.stack_id = stack_id

        self.status: StackInstanceStatus = StackInstanceStatus.CURRENT
        self.stack_instance_status = StackInstanceComprehensiveStatus(
            DetailedStatus=StackInstanceDetailedStatus.SUCCEEDED
        )


class StackSet:
    stack_instances: list[StackInstance]
    operations: dict[str, StackSetOperation]

    def __init__(self, account_id: str, region_name: str, request_payload: CreateStackSetInput):
        self.account_id = account_id
        self.region_name = region_name

        self.stack_set_name = request_payload["StackSetName"]
        self.stack_set_id = f"{self.stack_set_name}:{long_uid()}"
        self.template_body = request_payload.get("TemplateBody")
        self.template_url = request_payload.get("TemplateURL")

        self.stack_instances = []
        self.operations = {}
