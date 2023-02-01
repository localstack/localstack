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


# TODO
class StateMachine:
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
        self.name: Name = name
        self.arn: Arn = arn
        self.definition: Definition = definition
        self.role_arn: Arn = role_arn
        self.create_date: datetime = create_date or datetime.now()
        self.sm_type: StateMachineType = sm_type or StateMachineType.STANDARD
        self.logging_config: Optional[LoggingConfiguration] = logging_config
        self.tags: Optional[TagList] = tags
        self.tracing_config: Optional[TracingConfiguration] = tracing_config

    def to_state_machine_list_item(self) -> StateMachineListItem:
        return StateMachineListItem(
            stateMachineArn=self.arn,
            name=self.name,
            type=self.sm_type,
            creationDate=self.create_date,
        )
