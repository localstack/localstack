from __future__ import annotations

import base64
import logging
from typing import TypedDict

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.core import ServiceException
from localstack.aws.api.events import (
    CreateEventBusResponse,
    DescribeEventBusResponse,
    EventBusName,
    EventBusNameOrArn,
    EventsApi,
    EventSourceName,
    InternalException,
    LimitMax100,
    ListEventBusesResponse,
    ListRulesResponse,
    NextToken,
    ResourceNotFoundException,
    RuleName,
    TagList,
)
from localstack.services.events.event_bus import (
    EventBus,
    EventBusDict,
    event_bus_to_api_type_event_bus,
    event_bust_dict_to_list,
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

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        event_buses = (
            self._get_filtered_event_buses(name_prefix) if name_prefix else self._event_buses
        )
        event_buses_length = len(event_buses)
        start_index = self._decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else event_buses_length
        limited_event_buses_list = dict(list(event_buses.items())[start_index:end_index])

        next_token = (
            self._encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all event buses are returned
            if end_index <= event_buses_length
            else None
        )

        return {
            "EventBuses": event_bust_dict_to_list(limited_event_buses_list),
            "NextToken": next_token,
        }

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        event_bus_key = self._extract_event_bus_name(name)
        event_bus = self._get_event_bus(event_bus_key, context.region)
        return event_bus_to_api_type_event_bus(event_bus)

    @handler("ListRules")
    def list_rules(
        self,
        context: RequestContext,
        name_prefix: RuleName = None,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRulesResponse:
        return {"Rules": []}

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

    def _get_filtered_event_buses(self, name_prefix: EventBusName) -> EventBusDict:
        return {
            key: event_bus
            for key, event_bus in self._event_buses.items()
            if event_bus.name.startswith(name_prefix)
        }

    def _encode_next_token(self, token: int) -> NextToken:
        return base64.b64encode(token.to_bytes(128, "big")).decode("utf-8")

    def _decode_next_token(self, token: NextToken) -> int:
        return int.from_bytes(base64.b64decode(token), "big")


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
