from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Optional, TypeAlias, TypedDict

from bson import Timestamp

from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import (
    Arn,
    CreatedBy,
    EventBusName,
    EventPattern,
    EventResourceList,
    EventSourceName,
    ManagedBy,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
    Target,
    TargetId,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.tagging import TaggingService

TargetDict = dict[TargetId, Target]


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
    arn: Arn = field(init=False)

    def __post_init__(self):
        if self.event_bus_name == "default":
            self.arn = f"arn:aws:events:{self.region}:{self.account_id}:rule/{self.name}"
        else:
            self.arn = f"arn:aws:events:{self.region}:{self.account_id}:rule/{self.event_bus_name}/{self.name}"
        self.created_by = self.account_id
        if self.tags is None:
            self.tags = []
        if self.targets is None:
            self.targets = {}
        if self.state is None:
            self.state = RuleState.ENABLED


RuleDict = dict[RuleName, Rule]


@dataclass
class EventBus:
    name: EventBusName
    region: str
    account_id: str
    event_source_name: Optional[str] = None
    tags: TagList = field(default_factory=list)
    policy: Optional[ResourcePolicy] = None
    rules: RuleDict = field(default_factory=dict)
    arn: Arn = field(init=False)
    creation_time: Optional[Timestamp] = None
    last_modified_time: Optional[Timestamp] = None

    def __post_init__(self):
        self.arn = f"arn:aws:events:{self.region}:{self.account_id}:event-bus/{self.name}"
        if self.rules is None:
            self.rules = {}
        if self.tags is None:
            self.tags = []


EventBusDict = dict[EventBusName, EventBus]


class EventsStore(BaseStore):
    # Map of eventbus names to eventbus objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    event_buses: EventBusDict = LocalAttribute(default=dict)

    # Maps resource ARN to tags
    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


events_store = AccountRegionBundle("events", EventsStore)


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


class InvalidEventPatternException(Exception):
    reason: str

    def __init__(self, reason=None, message=None) -> None:
        self.reason = reason
        self.message = message or f"Event pattern is not valid. Reason: {reason}"


class FormattedEvent(TypedDict):
    version: str
    id: str
    detail_type: Optional[str]  # key "detail-type" is automatically interpreted as detail_type
    source: Optional[EventSourceName]
    account: str
    time: str
    region: str
    resources: Optional[EventResourceList]
    detail: dict[str, str | dict]


TransformedEvent: TypeAlias = FormattedEvent | dict | str


class ResourceType(Enum):
    EVENT_BUS = "event_bus"
    RULE = "rule"
