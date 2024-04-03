from typing import TypedDict

from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import EventBusName
from localstack.services.events.event_bus import EventBus
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    LocalAttribute,
)


class Event(TypedDict, total=False):
    version: str
    id: str
    source: str
    account: str
    time: str
    region: str
    resources: list[str]
    detail_type: str
    detail: dict
    additional_attributes: dict


EventList = list[Event]


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


class EventsStore(BaseStore):
    # Map of eventbus names to eventbus objects. The name MUST be unique per account and region (works with AccountRegionBundle)
    event_bus: dict[EventBusName, EventBus] = LocalAttribute(default=dict)


events_store = AccountRegionBundle("events", EventsStore)
