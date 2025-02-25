import datetime
import random
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    AliasDescription,
    Arn,
    CharacterRestrictedName,
    DescribeStateMachineAliasOutput,
    RoutingConfigurationList,
    StateMachineAliasListItem,
)


class Alias:
    _mutex: Final[threading.Lock]
    _update_date: Optional[datetime.datetime]
    _name: Final[CharacterRestrictedName]
    _description: Optional[AliasDescription]
    _routing_configuration_list: RoutingConfigurationList
    _state_machine_version_arns: list[Arn]
    _execution_probability_distribution: list[int]
    state_machine_alias_arn: Final[Arn]
    create_date: datetime.datetime

    def __init__(
        self,
        state_machine_arn: Arn,
        name: CharacterRestrictedName,
        description: Optional[AliasDescription],
        routing_configuration_list: RoutingConfigurationList,
    ):
        self._mutex = threading.Lock()
        self._update_date = None
        self._name = name
        self._description = None
        self.state_machine_alias_arn = f"{state_machine_arn}:{name}"
        self.update(description=description, routing_configuration_list=routing_configuration_list)
        self.create_date = self._get_mutex_date()

    def __hash__(self):
        return hash(self.state_machine_alias_arn)

    def __eq__(self, other):
        if isinstance(other, Alias):
            return self.state_machine_alias_arn == other.state_machine_alias_arn
        return False

    @staticmethod
    def _get_mutex_date() -> datetime.datetime:
        return datetime.datetime.now(tz=datetime.timezone.utc)

    def update(
        self,
        description: Optional[AliasDescription],
        routing_configuration_list: RoutingConfigurationList,
    ) -> None:
        with self._mutex:
            self._update_date = self._get_mutex_date()

            if description is not None:
                self._description = description

            if routing_configuration_list:
                self._routing_configuration_list = routing_configuration_list
                self._state_machine_version_arns = list()
                self._execution_probability_distribution = list()
                for routing_configuration in routing_configuration_list:
                    self._state_machine_version_arns.append(
                        routing_configuration["stateMachineVersionArn"]
                    )
                    self._execution_probability_distribution.append(routing_configuration["weight"])

    def sample(self):
        with self._mutex:
            samples = random.choices(
                self._state_machine_version_arns,
                weights=self._execution_probability_distribution,
                k=1,
            )
            state_machine_version_arn = samples[0]
            return state_machine_version_arn

    def to_description(self) -> DescribeStateMachineAliasOutput:
        with self._mutex:
            description = DescribeStateMachineAliasOutput(
                creationDate=self.create_date,
                name=self._name,
                description=self._description,
                routingConfiguration=self._routing_configuration_list,
            )
            if self._update_date is not None:
                description["updateDate"] = self._update_date
            return description

    def to_item(self) -> StateMachineAliasListItem:
        return StateMachineAliasListItem(
            stateMachineAliasArn=self.state_machine_alias_arn, creationDate=self.create_date
        )
