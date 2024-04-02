from __future__ import annotations

import logging
from typing import TypedDict

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import (
    CreateEventBusResponse,
    EventBusName,
    EventBusNameOrArn,
    EventsApi,
    EventSourceName,
    InternalException,
    ResourceNotFoundException,
    TagList,
)
from localstack.services.events.event_bus import (
    EventBus,
    EventBusDict,
)
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class EventsProvider(EventsApi, ServiceLifecycleHook):
    def __init__(self):
        self._event_buses: EventBusDict = {}
        self._events_workers = {}
        self._add_default_event_bus()

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        event_bus_arn = self._get_event_bus_arn(name, context.region, context.account_id)
        event_bus = EventBus(name, event_bus_arn)
        event_bus_key = self._get_event_bus_key(name, context.region)
        self._event_buses[event_bus_key] = event_bus

        response = CreateEventBusResponse(
            EventBusArn=event_bus_arn,
        )
        return response

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        if name == "default":
            raise InternalException("ValidationException", "Cannot delete event bus default.")
        event_bus_key = self._get_event_bus_key(name, context.region)
        if event_bus := self._event_buses.pop(event_bus_key):
            event_bus.delete()
        else:
            raise ResourceNotFoundException(f"EventBus {name} does not exist")

    def _add_default_event_bus(self) -> None:
        name = "default"
        default_account_id = "000000000000"
        default_region = "us-east-1"
        arn = self._get_event_bus_arn(name, default_region, default_account_id)
        self._event_buses["default"] = EventBus(name, arn)

    def _extract_event_bus_name(
        self, event_bus_name_or_arn: EventBusNameOrArn | None
    ) -> EventBusName:
        if not event_bus_name_or_arn:
            return "default"
        return event_bus_name_or_arn.split("/")[-1]

    def _get_event_bus(self, name: EventBusName, region: str) -> EventBus:
        event_bus_key = self._get_event_bus_key(name, region)
        if event_bus_key not in self._event_buses:
            raise ResourceNotFoundException(f"EventBus {name} does not exist")
        return self._event_buses[event_bus_key]

    def _get_event_bus_key(self, name: EventBusName, region: str) -> str:
        return f"{name}-{region}"

    def _get_event_bus_arn(self, name: EventBusName, region: str, account_id: str) -> str:
        return f"arn:aws:events:{region}:{account_id}:event-bus/{name}"


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
