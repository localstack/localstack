from datetime import datetime, timezone
from typing import NotRequired, Optional, TypedDict

from localstack.aws.api.cloudformation import (
    ChangeSetStatus,
    ChangeSetType,
    CreateChangeSetInput,
    CreateStackInput,
    ExecutionStatus,
    Output,
    Parameter,
    ResourceStatus,
    StackDriftInformation,
    StackDriftStatus,
    StackEvent,
    StackResource,
    StackStatus,
    StackStatusReason,
)
from localstack.aws.api.cloudformation import (
    Stack as ApiStack,
)
from localstack.services.cloudformation.engine.entities import (
    StackIdentifier,
)
from localstack.services.cloudformation.engine.v2.change_set_model import (
    NodeTemplate,
)
from localstack.utils.aws import arns
from localstack.utils.strings import long_uid, short_uid


class ResolvedResource(TypedDict):
    Properties: dict


class Stack:
    stack_name: str
    parameters: list[Parameter]
    change_set_id: str | None
    status: StackStatus
    status_reason: StackStatusReason | None
    stack_id: str
    creation_time: datetime
    deletion_time: datetime | None
    events = list[StackEvent]

    # state after deploy
    resolved_parameters: dict[str, str]
    resolved_resources: dict[str, ResolvedResource]
    resolved_outputs: dict[str, str]
    resource_states: dict[str, StackResource]

    def __init__(
        self,
        account_id: str,
        region_name: str,
        request_payload: CreateChangeSetInput | CreateStackInput,
        template: dict | None = None,
        template_body: str | None = None,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.template = template
        self.template_body = template_body
        self.status = StackStatus.CREATE_IN_PROGRESS
        self.status_reason = None
        self.change_set_ids = []
        self.creation_time = datetime.now(tz=timezone.utc)
        self.deletion_time = None
        self.change_set_id = None

        self.stack_name = request_payload["StackName"]
        self.parameters = request_payload.get("Parameters", [])
        self.stack_id = arns.cloudformation_stack_arn(
            self.stack_name,
            stack_id=StackIdentifier(
                account_id=self.account_id, region=self.region_name, stack_name=self.stack_name
            ).generate(tags=request_payload.get("Tags")),
            account_id=self.account_id,
            region_name=self.region_name,
        )

        # TODO: only kept for v1 compatibility
        self.request_payload = request_payload

        # state after deploy
        self.resolved_parameters = {}
        self.resolved_resources = {}
        self.resolved_outputs = {}
        self.resource_states = {}
        self.events = []

    def set_stack_status(self, status: StackStatus, reason: StackStatusReason | None = None):
        self.status = status
        if reason:
            self.status_reason = reason

        self._store_event(self.stack_name, self.stack_id, status.value, status_reason=reason)

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
            Timestamp=datetime.now(tz=timezone.utc),
            ResourceStatus=status,
            ResourceStatusReason=resource_status_reason,
        )

        if not resource_status_reason:
            resource_description.pop("ResourceStatusReason")

        self.resource_states[logical_resource_id] = resource_description
        self._store_event(logical_resource_id, physical_resource_id, status, resource_status_reason)

    def _store_event(
        self,
        resource_id: str = None,
        physical_res_id: str = None,
        status: str = "",
        status_reason: str = "",
    ):
        resource_id = resource_id
        physical_res_id = physical_res_id
        resource_type = (
            self.template.get("Resources", {})
            .get(resource_id, {})
            .get("Type", "AWS::CloudFormation::Stack")
        )

        event: StackEvent = {
            "EventId": long_uid(),
            "Timestamp": datetime.now(tz=timezone.utc),
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

    def describe_details(self) -> ApiStack:
        result = {
            "CreationTime": self.creation_time,
            "DeletionTime": self.deletion_time,
            "StackId": self.stack_id,
            "StackName": self.stack_name,
            "StackStatus": self.status,
            "StackStatusReason": self.status_reason,
            # fake values
            "DisableRollback": False,
            "DriftInformation": StackDriftInformation(
                StackDriftStatus=StackDriftStatus.NOT_CHECKED
            ),
            "EnableTerminationProtection": False,
            "LastUpdatedTime": self.creation_time,
            "RollbackConfiguration": {},
            "Tags": [],
        }
        if change_set_id := self.change_set_id:
            result["ChangeSetId"] = change_set_id

        if self.resolved_outputs:
            describe_outputs = []
            for key, value in self.resolved_outputs.items():
                describe_outputs.append(
                    Output(
                        # TODO(parity): Description, ExportName
                        # TODO(parity): what happens on describe stack when the stack has not been deployed yet?
                        OutputKey=key,
                        OutputValue=value,
                    )
                )
            result["Outputs"] = describe_outputs
        return result


class ChangeSetRequestPayload(TypedDict, total=False):
    ChangeSetName: str
    ChangeSetType: NotRequired[ChangeSetType]


class ChangeSet:
    change_set_name: str
    change_set_id: str
    change_set_type: ChangeSetType
    update_model: Optional[NodeTemplate]
    status: ChangeSetStatus
    execution_status: ExecutionStatus
    creation_time: datetime

    def __init__(
        self,
        stack: Stack,
        request_payload: ChangeSetRequestPayload,
        template: dict | None = None,
    ):
        self.stack = stack
        self.template = template
        self.status = ChangeSetStatus.CREATE_IN_PROGRESS
        self.execution_status = ExecutionStatus.AVAILABLE
        self.update_model = None
        self.creation_time = datetime.now(tz=timezone.utc)

        self.change_set_name = request_payload["ChangeSetName"]
        self.change_set_type = request_payload.get("ChangeSetType", ChangeSetType.UPDATE)
        self.change_set_id = arns.cloudformation_change_set_arn(
            self.change_set_name,
            change_set_id=short_uid(),
            account_id=self.stack.account_id,
            region_name=self.stack.region_name,
        )

    def set_update_model(self, update_model: NodeTemplate) -> None:
        self.update_model = update_model

    def set_change_set_status(self, status: ChangeSetStatus):
        self.status = status

    def set_execution_status(self, execution_status: ExecutionStatus):
        self.execution_status = execution_status

    @property
    def account_id(self) -> str:
        return self.stack.account_id

    @property
    def region_name(self) -> str:
        return self.stack.region_name
