import json
from datetime import datetime, timezone
from typing import Optional

from localstack.aws.api.events import (
    Action,
    Arn,
    Condition,
    EventBusName,
    Principal,
    ResourceNotFoundException,
    StatementId,
    TagList,
)
from localstack.services.events.models import EventBus, ResourcePolicy, RuleDict, Statement


class EventBusService:
    name: EventBusName
    region: str
    account_id: str
    event_source_name: str | None
    tags: TagList | None
    policy: str | None
    rules: RuleDict | None
    event_bus: EventBus

    def __init__(
        self,
        name: EventBusName,
        region: str,
        account_id: str,
        event_source_name: Optional[str] = None,
        tags: Optional[TagList] = None,
        policy: Optional[str] = None,
        rules: Optional[RuleDict] = None,
    ):
        self.event_bus = EventBus(
            name,
            region,
            account_id,
            event_source_name,
            tags,
            policy,
            rules,
        )

    @property
    def arn(self) -> Arn:
        return self.event_bus.arn

    def put_permission(
        self,
        action: Action,
        principal: Principal,
        statement_id: StatementId,
        condition: Condition,
        policy: str,
    ):
        if policy and any([action, principal, statement_id, condition]):
            raise ValueError("Combination of policy with other arguments is not allowed")
        self.event_bus.last_modified_time = datetime.now(timezone.utc)
        if policy:  # policy document replaces all existing permissions
            policy = json.loads(policy)
            parsed_policy = ResourcePolicy(**policy)
            self.event_bus.policy = parsed_policy
        else:
            permission_statement = self._parse_statement(
                statement_id, action, principal, self.arn, condition
            )

            if existing_policy := self.event_bus.policy:
                if permission_statement["Principal"] == "*":
                    for statement in existing_policy["Statement"]:
                        if "*" == statement["Principal"]:
                            return
                existing_policy["Statement"].append(permission_statement)
            else:
                parsed_policy = ResourcePolicy(
                    Version="2012-10-17", Statement=[permission_statement]
                )
                self.event_bus.policy = parsed_policy

    def revoke_put_events_permission(self, statement_id: str):
        policy = self.event_bus.policy
        if not policy or not any(
            statement.get("Sid") == statement_id for statement in policy["Statement"]
        ):
            raise ResourceNotFoundException("Statement with the provided id does not exist.")
        if policy:
            policy["Statement"] = [
                statement
                for statement in policy["Statement"]
                if statement.get("Sid") != statement_id
            ]
            self.event_bus.last_modified_time = datetime.now(timezone.utc)

    def _parse_statement(
        self,
        statement_id: StatementId,
        action: Action,
        principal: Principal,
        resource_arn: Arn,
        condition: Condition,
    ) -> Statement:
        if condition and principal != "*":
            raise ValueError("Condition can only be set when principal is '*'")
        if principal != "*":
            principal = {"AWS": f"arn:aws:iam::{principal}:root"}
        statement = Statement(
            Sid=statement_id,
            Effect="Allow",
            Principal=principal,
            Action=action,
            Resource=resource_arn,
            Condition=condition,
        )
        return statement


EventBusServiceDict = dict[Arn, EventBusService]
