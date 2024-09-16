from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional, TypeAlias, TypedDict

from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import (
    ArchiveDescription,
    ArchiveName,
    ArchiveState,
    Arn,
    CreatedBy,
    EventBusName,
    EventPattern,
    EventResourceList,
    EventSourceName,
    EventTime,
    ManagedBy,
    ReplayDescription,
    ReplayDestination,
    ReplayName,
    ReplayState,
    ReplayStateReason,
    RetentionDays,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
    Target,
    TargetId,
    Timestamp,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws.arns import (
    event_bus_arn,
    events_archive_arn,
    events_replay_arn,
    events_rule_arn,
)
from localstack.utils.tagging import TaggingService

TargetDict = dict[TargetId, Target]


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


class InvalidEventPatternException(Exception):
    reason: str

    def __init__(self, reason=None, message=None) -> None:
        self.reason = reason
        self.message = message or f"Event pattern is not valid. Reason: {reason}"


FormattedEvent = TypedDict(  # functional syntax required due to name-name keys
    "FormattedEvent",
    {
        "version": str,
        "id": str,
        "detail-type": Optional[str],
        "source": Optional[EventSourceName],
        "account": str,
        "time": EventTime,
        "region": str,
        "resources": Optional[EventResourceList],
        "detail": dict[str, str | dict],
        "replay-name": Optional[ReplayName],
        "event-bus-name": EventBusName,
    },
)


FormattedEventDict = dict[str, FormattedEvent]
FormattedEventList = list[FormattedEvent]

TransformedEvent: TypeAlias = FormattedEvent | dict | str


class ResourceType(Enum):
    EVENT_BUS = "event_bus"
    RULE = "rule"


class Condition(TypedDict):
    Type: Literal["StringEquals"]
    Key: Literal["aws:PrincipalOrgID"]
    Value: str


class Statement(TypedDict):
    Sid: str
    Effect: str
    Principal: str | dict[str, str]
    Action: str
    Resource: str
    Condition: Condition


class ResourcePolicy(TypedDict):
    Version: str
    Statement: list[Statement]


@dataclass
class Rule:
    name: RuleName
    region: str
    account_id: str
    schedule_expression: Optional[ScheduleExpression] = None
    event_pattern: Optional[EventPattern] = None
    state: Optional[RuleState] = None
    description: Optional[RuleDescription] = None
    role_arn: Optional[RoleArn] = None
    tags: TagList = field(default_factory=list)
    event_bus_name: EventBusName = "default"
    targets: TargetDict = field(default_factory=dict)
    managed_by: Optional[ManagedBy] = None  # can only be set by AWS services
    created_by: CreatedBy = field(init=False)

    def __post_init__(self):
        self.created_by = self.account_id
        if self.tags is None:
            self.tags = []
        if self.targets is None:
            self.targets = {}
        if self.state is None:
            self.state = RuleState.ENABLED

    @property
    def arn(self) -> Arn:
        return events_rule_arn(self.name, self.account_id, self.region, self.event_bus_name)


RuleDict = dict[RuleName, Rule]


@dataclass
class Replay:
    name: str
    region: str
    account_id: str
    event_source_arn: Arn
    destination: ReplayDestination  # Event Bus Arn or Rule Arns
    event_start_time: Timestamp
    event_end_time: Timestamp
    description: Optional[ReplayDescription] = None
    state: Optional[ReplayState] = None
    state_reason: Optional[ReplayStateReason] = None
    event_last_replayed_time: Optional[Timestamp] = None
    replay_start_time: Optional[Timestamp] = None
    replay_end_time: Optional[Timestamp] = None

    @property
    def arn(self) -> Arn:
        return events_replay_arn(self.name, self.account_id, self.region)


ReplayDict = dict[ReplayName, Replay]


@dataclass
class Archive:
    name: ArchiveName
    region: str
    account_id: str
    event_source_arn: Arn
    description: ArchiveDescription = None
    event_pattern: EventPattern = None
    retention_days: RetentionDays = None
    state: ArchiveState = ArchiveState.DISABLED
    creation_time: Timestamp = None
    size_bytes: int = 0  # TODO how to deal with updating this value?
    events: FormattedEventDict = field(default_factory=dict)

    @property
    def arn(self) -> Arn:
        return events_archive_arn(self.name, self.account_id, self.region)

    @property
    def event_count(self) -> int:
        return len(self.events)


ArchiveDict = dict[ArchiveName, Archive]


@dataclass
class EventBus:
    name: EventBusName
    region: str
    account_id: str
    event_source_name: Optional[str] = None
    tags: TagList = field(default_factory=list)
    policy: Optional[ResourcePolicy] = None
    rules: RuleDict = field(default_factory=dict)
    creation_time: Timestamp = field(init=False)
    last_modified_time: Timestamp = field(init=False)

    def __post_init__(self):
        self.creation_time = datetime.now(timezone.utc)
        self.last_modified_time = datetime.now(timezone.utc)
        if self.rules is None:
            self.rules = {}
        if self.tags is None:
            self.tags = []

    @property
    def arn(self) -> Arn:
        return event_bus_arn(self.name, self.account_id, self.region)


EventBusDict = dict[EventBusName, EventBus]


class EventsStore(BaseStore):
    # Map of eventbus names to eventbus objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    event_buses: EventBusDict = LocalAttribute(default=dict)

    # Map of archive names to archive objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    archives: ArchiveDict = LocalAttribute(default=dict)

    # Map of replay names to replay objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    replays: ReplayDict = LocalAttribute(default=dict)

    # Maps resource ARN to tags
    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


events_store = AccountRegionBundle("events", EventsStore)
