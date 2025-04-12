from localstack.aws.api.cloudformation import Parameter
from localstack.services.cloudformation.engine.entities import (
    StackIdentifier,
    StackMetadata,
    StackTemplate,
)
from localstack.utils.aws import arns


class Stack:
    change_set_ids: list[str]
    stack_name: str
    parameters: list[Parameter]
    change_set_name: str | None
    status: str

    def __init__(
        self,
        account_id: str,
        region_name: str,
        metadata: StackMetadata | None = None,
        template: StackTemplate | None = None,
        template_body: str | None = None,
    ):
        self.account_id = account_id
        self.region_name = region_name
        self.template = template
        self.template_body = template_body
        self.status = "CREATE_IN_PROGRESS"

        if metadata:
            self._populate_from_metadata(metadata)

    def set_stack_status(self, status: str):
        self.status = status

    def _populate_from_metadata(self, metadata: StackMetadata):
        self.stack_name = metadata["StackName"]
        self.change_set_name = metadata.get("ChangeSetName")
        self.parameters = metadata["Parameters"]
        self.stack_id = arns.cloudformation_stack_arn(
            self.stack_name,
            stack_id=StackIdentifier(
                account_id=self.account_id, region=self.region_name, stack_name=self.stack_name
            ).generate(tags=metadata.get("tags")),
            account_id=self.account_id,
            region_name=self.region_name,
        )


class StackChangeSet:
    pass
