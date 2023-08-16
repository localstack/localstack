import json
from datetime import datetime
from typing import Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    Definition,
    DescribeStateMachineOutput,
    LoggingConfiguration,
    Name,
    RevisionId,
    StateMachineListItem,
    StateMachineStatus,
    StateMachineType,
    TagList,
    TracingConfiguration,
)
from localstack.utils.strings import long_uid


class StateMachine:
    name: Name
    arn: Arn
    revision_id: Optional[RevisionId]
    definition: Definition
    role_arn: Arn
    create_date: datetime
    sm_type: StateMachineType
    logging_config: Optional[LoggingConfiguration]
    tags: Optional[TagList]
    tracing_config: Optional[TracingConfiguration]

    def __init__(
        self,
        name: Name,
        arn: Arn,
        definition: Definition,
        role_arn: Arn,
        create_date: Optional[datetime] = None,
        sm_type: Optional[StateMachineType] = None,
        logging_config: Optional[LoggingConfiguration] = None,
        tags: Optional[TagList] = None,
        tracing_config: Optional[TracingConfiguration] = None,
    ):
        self.name = name
        self.arn = arn
        self.revision_id = None
        self.definition = definition
        self.role_arn = role_arn
        self.create_date = create_date or datetime.now()
        self.sm_type = sm_type or StateMachineType.STANDARD
        self.logging_config = logging_config
        self.tags = tags
        self.tracing_config = tracing_config

    def add_revision(
        self, definition: Optional[str], role_arn: Optional[Arn]
    ) -> Optional[RevisionId]:
        update_definition = definition and json.loads(definition) != json.loads(self.definition)
        if update_definition:
            self.definition = definition

        update_role_arn = role_arn and role_arn != self.role_arn
        if update_role_arn:
            self.role_arn = role_arn

        if any([update_definition, update_role_arn]):
            self.revision_id = long_uid()

        return self.revision_id

    def to_state_machine_list_item(self) -> StateMachineListItem:
        return StateMachineListItem(
            stateMachineArn=self.arn,
            name=self.name,
            type=self.sm_type,
            creationDate=self.create_date,
        )

    def to_describe_output(self) -> DescribeStateMachineOutput:
        describe_output = DescribeStateMachineOutput(
            stateMachineArn=self.arn,
            name=self.name,
            status=StateMachineStatus.ACTIVE,
            definition=self.definition,
            roleArn=self.role_arn,
            type=self.sm_type,
            creationDate=self.create_date,
            loggingConfiguration=self.logging_config,
        )
        if self.revision_id:
            describe_output["revisionId"] = self.revision_id
        return describe_output
