import re
from typing import Callable, Optional

from localstack.aws.api.events import (
    Arn,
    EventBusName,
    EventPattern,
    LimitExceededException,
    ManagedBy,
    PutTargetsResultEntryList,
    RemoveTargetsResultEntryList,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
    Target,
    TargetIdList,
    TargetList,
)
from localstack.services.events.models import Rule, TargetDict, ValidationException
from localstack.services.events.scheduler import JobScheduler, convert_schedule_to_cron

TARGET_ID_REGEX = re.compile(r"^[\.\-_A-Za-z0-9]+$")
TARGET_ARN_REGEX = re.compile(r"arn:[\d\w:\-/]*")
RULE_SCHEDULE_CRON_REGEX = re.compile(r"^cron\(.*\)")
RULE_SCHEDULE_RATE_REGEX = re.compile(r"^rate\(\d*\s(minute|minutes|hour|hours|day|days)\)")


class RuleService:
    name: RuleName
    region: str
    account_id: str
    schedule_expression: ScheduleExpression | None
    event_pattern: EventPattern | None
    description: RuleDescription | None
    role_arn: Arn | None
    tags: TagList | None
    event_bus_name: EventBusName | None
    targets: TargetDict | None
    managed_by: ManagedBy
    rule: Rule

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
        targets: Optional[TargetDict] = None,
        managed_by: Optional[ManagedBy] = None,
    ):
        self._validate_input(event_pattern, schedule_expression, event_bus_name)
        if schedule_expression:
            self.schedule_cron = self._get_schedule_cron(schedule_expression)
        else:
            self.schedule_cron = None
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
            managed_by,
        )

    @property
    def arn(self) -> Arn:
        return self.rule.arn

    @property
    def state(self) -> RuleState:
        return self.rule.state

    def enable(self) -> None:
        self.rule.state = RuleState.ENABLED

    def disable(self) -> None:
        self.rule.state = RuleState.DISABLED

    def add_targets(self, targets: TargetList) -> PutTargetsResultEntryList:
        failed_entries = self.validate_targets_input(targets)
        for target in targets:
            target_id = target["Id"]
            if target_id not in self.rule.targets and self._check_target_limit_reached():
                raise LimitExceededException(
                    "The requested resource exceeds the maximum number allowed."
                )
            target = Target(**target)
            self.rule.targets[target_id] = target
        return failed_entries

    def remove_targets(
        self, target_ids: TargetIdList, force: bool = False
    ) -> RemoveTargetsResultEntryList:
        delete_errors = []
        for target_id in target_ids:
            if target_id in self.rule.targets:
                if self.rule.managed_by and not force:
                    delete_errors.append(
                        {
                            "TargetId": target_id,
                            "ErrorCode": "ManagedRuleException",
                            "ErrorMessage": f"Rule '{self.rule.name}' is managed by an AWS service can only be modified if force is True.",
                        }
                    )
                else:
                    del self.rule.targets[target_id]
            else:
                delete_errors.append(
                    {
                        "TargetId": target_id,
                        "ErrorCode": "ResourceNotFoundException",
                        "ErrorMessage": f"Rule '{self.rule.name}' does not have a target with the Id '{target_id}'.",
                    }
                )
        return delete_errors

    def create_schedule_job(self, schedule_job_sender_func: Callable) -> None:
        cron = self.schedule_cron
        state = self.rule.state != "DISABLED"
        self.job_id = JobScheduler.instance().add_job(schedule_job_sender_func, cron, state)

    def validate_targets_input(self, targets: TargetList) -> PutTargetsResultEntryList:
        validation_errors = []
        for index, target in enumerate(targets):
            id = target.get("Id")
            arn = target.get("Arn", "")
            if not TARGET_ID_REGEX.match(id):
                validation_errors.append(
                    {
                        "TargetId": id,
                        "ErrorCode": "ValidationException",
                        "ErrorMessage": f"Value '{id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+",
                    }
                )

            if len(id) > 64:
                validation_errors.append(
                    {
                        "TargetId": id,
                        "ErrorCode": "ValidationException",
                        "ErrorMessage": f"Value '{id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must have length less than or equal to 64",
                    }
                )

            if not TARGET_ARN_REGEX.match(arn):
                validation_errors.append(
                    {
                        "TargetId": id,
                        "ErrorCode": "ValidationException",
                        "ErrorMessage": f"Parameter {arn} is not valid. Reason: Provided Arn is not in correct format.",
                    }
                )

            if ":sqs:" in arn and arn.endswith(".fifo") and not target.get("SqsParameters"):
                validation_errors.append(
                    {
                        "TargetId": id,
                        "ErrorCode": "ValidationException",
                        "ErrorMessage": f"Parameter(s) SqsParameters must be specified for target: {id}.",
                    }
                )

        return validation_errors

    def _validate_input(
        self,
        event_pattern: Optional[EventPattern],
        schedule_expression: Optional[ScheduleExpression],
        event_bus_name: Optional[EventBusName] = "default",
    ) -> None:
        if not event_pattern and not schedule_expression:
            raise ValidationException(
                "Parameter(s) EventPattern or ScheduleExpression must be specified."
            )

        if schedule_expression:
            if event_bus_name != "default":
                raise ValidationException(
                    "ScheduleExpression is supported only on the default event bus."
                )
            if not (
                RULE_SCHEDULE_CRON_REGEX.match(schedule_expression)
                or RULE_SCHEDULE_RATE_REGEX.match(schedule_expression)
            ):
                raise ValidationException("Parameter ScheduleExpression is not valid.")

    def _check_target_limit_reached(self) -> bool:
        if len(self.rule.targets) >= 5:
            return True
        return False

    def _get_schedule_cron(self, schedule_expression: ScheduleExpression) -> str:
        try:
            cron = convert_schedule_to_cron(schedule_expression)
            return cron
        except ValueError as e:
            raise ValidationException("Parameter ScheduleExpression is not valid.") from e


RuleServiceDict = dict[Arn, RuleService]
