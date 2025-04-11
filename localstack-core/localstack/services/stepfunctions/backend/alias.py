from __future__ import annotations

import copy
import datetime
import random
import threading
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    AliasDescription,
    Arn,
    CharacterRestrictedName,
    DescribeStateMachineAliasOutput,
    PageToken,
    RoutingConfigurationList,
    StateMachineAliasListItem,
)
from localstack.utils.strings import token_generator


class Alias:
    _mutex: Final[threading.Lock]
    update_date: Optional[datetime.datetime]
    name: Final[CharacterRestrictedName]
    _description: Optional[AliasDescription]
    _routing_configuration_list: RoutingConfigurationList
    _state_machine_version_arns: list[Arn]
    _execution_probability_distribution: list[int]
    state_machine_alias_arn: Final[Arn]
    tokenized_state_machine_alias_arn: Final[PageToken]
    create_date: datetime.datetime

    def __init__(
        self,
        state_machine_arn: Arn,
        name: CharacterRestrictedName,
        description: Optional[AliasDescription],
        routing_configuration_list: RoutingConfigurationList,
    ):
        self._mutex = threading.Lock()
        self.update_date = None
        self.name = name
        self._description = None
        self.state_machine_alias_arn = f"{state_machine_arn}:{name}"
        self.tokenized_state_machine_alias_arn = token_generator(self.state_machine_alias_arn)
        self.update(description=description, routing_configuration_list=routing_configuration_list)
        self.create_date = self._get_mutex_date()

    def __hash__(self):
        return hash(self.state_machine_alias_arn)

    def __eq__(self, other):
        if isinstance(other, Alias):
            return self.is_idempotent(other=other)
        return False

    def is_idempotent(self, other: Alias) -> bool:
        return all(
            [
                self.state_machine_alias_arn == other.state_machine_alias_arn,
                self.name == other.name,
                self._description == other._description,
                self._routing_configuration_list == other._routing_configuration_list,
            ]
        )

    @staticmethod
    def _get_mutex_date() -> datetime.datetime:
        return datetime.datetime.now(tz=datetime.timezone.utc)

    def get_routing_configuration_list(self) -> RoutingConfigurationList:
        return copy.deepcopy(self._routing_configuration_list)

    def is_router_for(self, state_machine_version_arn: Arn) -> bool:
        with self._mutex:
            return state_machine_version_arn in self._state_machine_version_arns

    def update(
        self,
        description: Optional[AliasDescription],
        routing_configuration_list: RoutingConfigurationList,
    ) -> None:
        with self._mutex:
            self.update_date = self._get_mutex_date()

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
                name=self.name,
                description=self._description,
                routingConfiguration=self._routing_configuration_list,
                stateMachineAliasArn=self.state_machine_alias_arn,
            )
            if self.update_date is not None:
                description["updateDate"] = self.update_date
            return description

    def to_item(self) -> StateMachineAliasListItem:
        return StateMachineAliasListItem(
            stateMachineAliasArn=self.state_machine_alias_arn, creationDate=self.create_date
        )
