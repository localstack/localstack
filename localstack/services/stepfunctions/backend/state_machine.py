from datetime import datetime
from typing import Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    Definition,
    LoggingConfiguration,
    Name,
    StateMachineListItem,
    StateMachineType,
    TagList,
    TracingConfiguration,
)


class StateMachine:
    name: Name
    arn: Arn
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
        self.definition = definition
        self.role_arn = role_arn
        self.create_date = create_date or datetime.now()
        self.sm_type = sm_type or StateMachineType.STANDARD
        self.logging_config = logging_config
        self.tags = tags
        self.tracing_config = tracing_config

    def to_state_machine_list_item(self) -> StateMachineListItem:
        return StateMachineListItem(
            stateMachineArn=self.arn,
            name=self.name,
            type=self.sm_type,
            creationDate=self.create_date,
        )
