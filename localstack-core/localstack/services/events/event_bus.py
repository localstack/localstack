import json
from datetime import datetime, timezone
from typing import Optional

from localstack.aws.api.events import (
    Action,
    Arn,
    Condition,
    EventBusName,
    Principal,
    StatementId,
    String,
    TagList,
)
from localstack.services.events.models import EventBus, ResourcePolicy, RuleDict, Statement


class EventBusService:
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
    def arn(self):
        return self.event_bus.arn

    def put_permission(
        self,
        action: Action,
        principal: Principal,
        statement_id: StatementId,
        condition: Condition,
        policy: String,
    ):
        if policy and any([action, principal, statement_id, condition]):
            raise ValueError("Combination of policy with other arguments is not allowed")
        if policy:
            policy = json.loads(policy)
            parsed_policy = ResourcePolicy(**policy)
        else:
            permission_statement = self._pars_statement(
                statement_id, action, principal, self.arn, condition
            )
            parsed_policy = ResourcePolicy(Version="2012-10-17", Statement=[permission_statement])

        self.event_bus.policy = parsed_policy
        self.event_bus.creation_time = datetime.now(timezone.utc)
        self.event_bus.last_modified_time = datetime.now(timezone.utc)

    def revoke_put_events_permission(self, account_id: str):
        self.event_bus.policy = None

    def _pars_statement(self, statement_id, action, principal, resource_arn, condition):
        if condition and principal != "*":
            raise ValueError("Condition can only be set when principal is '*'")
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
