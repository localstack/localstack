import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional, TypeAlias, TypedDict

from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import (
    ApiDestinationDescription,
    ApiDestinationHttpMethod,
    ApiDestinationInvocationRateLimitPerSecond,
    ApiDestinationName,
    ApiDestinationState,
    ArchiveDescription,
    ArchiveName,
    ArchiveState,
    Arn,
    ConnectionArn,
    ConnectionAuthorizationType,
    ConnectionDescription,
    ConnectionName,
    ConnectionState,
    ConnectivityResourceParameters,
    CreateConnectionAuthRequestParameters,
    CreatedBy,
    EventBusName,
    EventPattern,
    EventResourceList,
    EventSourceName,
    EventTime,
    HttpsEndpoint,
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
    events_api_destination_arn,
    events_archive_arn,
    events_connection_arn,
    events_replay_arn,
    events_rule_arn,
)
from localstack.utils.strings import short_uid
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
    description: Optional[str] = None
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


@dataclass
class Connection:
    name: ConnectionName
    region: str
    account_id: str
    authorization_type: ConnectionAuthorizationType
    auth_parameters: CreateConnectionAuthRequestParameters
    state: ConnectionState
    secret_arn: Arn
    description: ConnectionDescription | None = None
    invocation_connectivity_parameters: ConnectivityResourceParameters | None = None
    creation_time: Timestamp = field(init=False)
    last_modified_time: Timestamp = field(init=False)
    last_authorized_time: Timestamp = field(init=False)
    tags: TagList = field(default_factory=list)
    id: str = str(uuid.uuid4())

    def __post_init__(self):
        timestamp_now = datetime.now(timezone.utc)
        self.creation_time = timestamp_now
        self.last_modified_time = timestamp_now
        self.last_authorized_time = timestamp_now
        if self.tags is None:
            self.tags = []

    @property
    def arn(self) -> Arn:
        return events_connection_arn(self.name, self.id, self.account_id, self.region)


ConnectionDict = dict[ConnectionName, Connection]


@dataclass
class ApiDestination:
    name: ApiDestinationName
    region: str
    account_id: str
    connection_arn: ConnectionArn
    invocation_endpoint: HttpsEndpoint
    http_method: ApiDestinationHttpMethod
    state: ApiDestinationState
    _invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond | None = None
    description: ApiDestinationDescription | None = None
    creation_time: Timestamp = field(init=False)
    last_modified_time: Timestamp = field(init=False)
    last_authorized_time: Timestamp = field(init=False)
    tags: TagList = field(default_factory=list)
    id: str = str(short_uid())

    def __post_init__(self):
        timestamp_now = datetime.now(timezone.utc)
        self.creation_time = timestamp_now
        self.last_modified_time = timestamp_now
        self.last_authorized_time = timestamp_now
        if self.tags is None:
            self.tags = []

    @property
    def arn(self) -> Arn:
        return events_api_destination_arn(self.name, self.id, self.account_id, self.region)

    @property
    def invocation_rate_limit_per_second(self) -> int:
        return self._invocation_rate_limit_per_second or 300  # Default value

    @invocation_rate_limit_per_second.setter
    def invocation_rate_limit_per_second(
        self, value: ApiDestinationInvocationRateLimitPerSecond | None
    ):
        self._invocation_rate_limit_per_second = value


ApiDestinationDict = dict[ApiDestinationName, ApiDestination]


class EventsStore(BaseStore):
    # Map of eventbus names to eventbus objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    event_buses: EventBusDict = LocalAttribute(default=dict)

    # Map of archive names to archive objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    archives: ArchiveDict = LocalAttribute(default=dict)

    # Map of replay names to replay objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    replays: ReplayDict = LocalAttribute(default=dict)

    # Map of connection names to connection objects.
    connections: ConnectionDict = LocalAttribute(default=dict)

    # Map of api destination names to api destination objects
    api_destinations: ApiDestinationDict = LocalAttribute(default=dict)

    # Maps resource ARN to tags
    TAGS: TaggingService = CrossRegionAttribute(default=TaggingService)


events_stores = AccountRegionBundle("events", EventsStore)
