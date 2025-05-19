from datetime import datetime, timezone
from typing import TypedDict

from localstack.aws.api.cloudformation import (
    ChangeSetStatus,
    ChangeSetType,
    CreateChangeSetInput,
    ExecutionStatus,
    Output,
    Parameter,
    StackDriftInformation,
    StackDriftStatus,
    StackStatus,
    StackStatusReason,
)
from localstack.aws.api.cloudformation import (
    Stack as ApiStack,
)
from localstack.services.cloudformation.engine.entities import (
    StackIdentifier,
    StackTemplate,
)
from localstack.services.cloudformation.engine.v2.change_set_model import (
    ChangeSetModel,
    NodeTemplate,
)
from localstack.utils.aws import arns
from localstack.utils.strings import short_uid


class ResolvedResource(TypedDict):
    Properties: dict


class Stack:
    stack_name: str
    parameters: list[Parameter]
    change_set_id: str | None
    change_set_name: str | None
    status: StackStatus
    status_reason: StackStatusReason | None
    stack_id: str
    creation_time: datetime

    # state after deploy
    resolved_parameters: dict[str, str]
    resolved_resources: dict[str, ResolvedResource]
    resolved_outputs: dict[str, str]

    def __init__(
        self,
        account_id: str,
        region_name: str,
        request_payload: CreateChangeSetInput,
        template: StackTemplate | None = None,
        template_body: str | None = None,
        change_set_ids: list[str] | None = None,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.template = template
        self.template_body = template_body
        self.status = StackStatus.CREATE_IN_PROGRESS
        self.status_reason = None
        self.change_set_ids = change_set_ids or []
        self.creation_time = datetime.now(tz=timezone.utc)

        self.stack_name = request_payload["StackName"]
        self.change_set_name = request_payload.get("ChangeSetName")
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

    def set_stack_status(self, status: StackStatus, reason: StackStatusReason | None = None):
        self.status = status
        if reason:
            self.status_reason = reason

    def describe_details(self) -> ApiStack:
        result = {
            "ChangeSetId": self.change_set_id,
            "CreationTime": self.creation_time,
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


class ChangeSet:
    change_set_name: str
    change_set_id: str
    change_set_type: ChangeSetType
    update_graph: NodeTemplate | None
    status: ChangeSetStatus
    execution_status: ExecutionStatus
    creation_time: datetime

    def __init__(
        self,
        stack: Stack,
        request_payload: CreateChangeSetInput,
        template: StackTemplate | None = None,
    ):
        self.stack = stack
        self.template = template
        self.status = ChangeSetStatus.CREATE_IN_PROGRESS
        self.execution_status = ExecutionStatus.AVAILABLE
        self.update_graph = None
        self.creation_time = datetime.now(tz=timezone.utc)

        self.change_set_name = request_payload["ChangeSetName"]
        self.change_set_type = request_payload.get("ChangeSetType", ChangeSetType.UPDATE)
        self.change_set_id = arns.cloudformation_change_set_arn(
            self.change_set_name,
            change_set_id=short_uid(),
            account_id=self.stack.account_id,
            region_name=self.stack.region_name,
        )

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

    def populate_update_graph(
        self,
        before_template: dict | None = None,
        after_template: dict | None = None,
        before_parameters: dict | None = None,
        after_parameters: dict | None = None,
    ) -> None:
        change_set_model = ChangeSetModel(
            before_template=before_template,
            after_template=after_template,
            before_parameters=before_parameters,
            after_parameters=after_parameters,
        )
        self.update_graph = change_set_model.get_update_model()
