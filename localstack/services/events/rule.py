import re
from typing import Optional

from localstack.aws.api.events import (
    Arn,
    EventBusName,
    EventPattern,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
)
from localstack.services.events.models_v2 import Rule, ValidationException


class RuleWorker:
    def __init__(
        self,
        name: RuleName,
        region: Optional[str] = None,
        account_id: Optional[str] = None,
        schedule_expression: Optional[ScheduleExpression] = None,
        event_pattern: Optional[EventPattern] = None,
        state: Optional[RuleState] = None,
        description: Optional[RuleDescription] = None,
        role_arn: Optional[RoleArn] = None,
        tags: Optional[TagList] = None,
        event_bus_name: Optional[EventBusName] = None,
        targets: Optional[TagList] = None,
    ):
        self._validate_input(event_pattern, schedule_expression, event_bus_name)
        # required to keep data and functionality separate for persistence
        self.rule = Rule(
            name,
            region,
            account_id,
            schedule_expression,
            event_pattern,
            state,
            description,
            role_arn,
            tags,
            event_bus_name,
            targets,
        )

    @property
    def arn(self):
        return self.rule.arn

    @property
    def state(self):
        return self.rule.state

    def enable(self):
        self.rule.state = RuleState.ENABLED

    def disable(self):
        self.rule.state = RuleState.DISABLED

    def delete(self):
        if len(self.rule.targets) > 0:
            raise ValidationException("Rule can't be deleted since it has targets.")
        self.rule.state = RuleState.DISABLED

    def _validate_input(
        self,
        event_pattern: Optional[EventPattern],
        schedule_expression: Optional[ScheduleExpression],
        event_bus_name: Optional[EventBusName] = "default",
    ):
        cron_regex = re.compile(r"^cron\(.*\)")
        rate_regex = re.compile(r"^rate\(\d*\s(minute|minutes|hour|hours|day|days)\)")

        if not event_pattern and not schedule_expression:
            raise ValidationException(
                "Parameter(s) EventPattern or ScheduleExpression must be specified."
            )

        if schedule_expression:
            if event_bus_name != "default":
                raise ValidationException(
                    "ScheduleExpression is supported only on the default event bus."
                )
            if not (cron_regex.match(schedule_expression) or rate_regex.match(schedule_expression)):
                raise ValidationException("Parameter ScheduleExpression is not valid.")


RuleWorkerDict = dict[Arn, RuleWorker]
