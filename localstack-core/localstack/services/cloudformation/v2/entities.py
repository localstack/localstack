from typing import TypedDict

from localstack.aws.api.cloudformation import (
    ChangeSetStatus,
    ChangeSetType,
    CreateChangeSetInput,
    ExecutionStatus,
    Parameter,
    StackStatus,
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
    pass


class Stack:
    stack_name: str
    parameters: list[Parameter]
    change_set_name: str | None
    status: StackStatus
    stack_id: str

    # state after deploy
    resolved_parameters: dict[str, str]
    resolved_resources: dict[str, ResolvedResource]

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
        self.change_set_ids = change_set_ids or []

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

    def set_stack_status(self, status: StackStatus):
        self.status = status

    def describe_details(self) -> dict:
        return {
            "StackId": self.stack_id,
            "StackName": self.stack_name,
            "StackStatus": self.status,
        }


class ChangeSet:
    change_set_name: str
    change_set_id: str
    change_set_type: ChangeSetType
    update_graph: NodeTemplate | None
    status: ChangeSetStatus
    execution_status: ExecutionStatus

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
            extra_context={"previous_resources": self.stack.resolved_resources},
        )
        self.update_graph = change_set_model.get_update_model()
