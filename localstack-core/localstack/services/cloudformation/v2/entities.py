from typing import TypedDict

from localstack.aws.api.cloudformation import ChangeSetType, CreateChangeSetInput, Parameter
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
    change_set_ids: list[str]
    stack_name: str
    parameters: list[Parameter]
    change_set_name: str | None
    status: str
    stack_id: str

    # state after deploy
    resolved_parameters: dict[str, str]
    resolved_resources: dict[str, ResolvedResource]

    def __init__(
        self,
        account_id: str,
        region_name: str,
        request_payload: CreateChangeSetInput | None = None,
        template: StackTemplate | None = None,
        template_body: str | None = None,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.template = template
        self.template_body = template_body
        self.status = "CREATE_IN_PROGRESS"

        # state after deploy
        self.resolved_parameters = {}
        self.resolved_resources = {}

        if request_payload:
            self.populate_from_request(request_payload)

    def set_stack_status(self, status: str):
        self.status = status

    def populate_from_request(self, request_payload: CreateChangeSetInput):
        self.stack_name = request_payload["StackName"]
        self.change_set_name = request_payload.get("ChangeSetName")
        self.parameters = request_payload["Parameters"]
        self.stack_id = arns.cloudformation_stack_arn(
            self.stack_name,
            stack_id=StackIdentifier(
                account_id=self.account_id, region=self.region_name, stack_name=self.stack_name
            ).generate(tags=request_payload.get("Tags")),
            account_id=self.account_id,
            region_name=self.region_name,
        )


class StackChangeSet:
    change_set_name: str
    change_set_id: str
    change_set_type: ChangeSetType
    update_graph: NodeTemplate

    def __init__(
        self,
        stack: Stack,
        request_payload: CreateChangeSetInput | None = None,
        template: StackTemplate | None = None,
    ):
        self.stack = stack
        self.template = template

        if request_payload:
            self.populate_from_request(request_payload)

    def populate_from_request(self, request_payload: CreateChangeSetInput):
        self.change_set_name = request_payload["ChangeSetName"]
        self.change_set_type = request_payload.get("ChangeSetType", ChangeSetType.UPDATE)
        self.change_set_id = arns.cloudformation_change_set_arn(
            self.change_set_name,
            change_set_id=short_uid(),
            account_id=self.stack.account_id,
            region_name=self.stack.region_name,
        )

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
