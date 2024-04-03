from __future__ import annotations

import base64
import logging

from localstack.aws.api import RequestContext, handler
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
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RuleName,
    TagList,
)
from localstack.services.events.event_bus import (
    EventBus,
    EventBusDict,
    event_bus_dict_to_api_type_event_bus,
    event_bust_dict_to_list,
)
from localstack.services.events.models_v2 import EventsStore, events_store
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class EventsProvider(EventsApi, ServiceLifecycleHook):
    def __init__(self):
        self._events_workers = {}

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        account_id = context.account_id
        region = context.region
        store = self._get_store(account_id, region)
        if name in store.event_bus.keys():
            raise ResourceAlreadyExistsException(f"Event bus {name} already exists.")
        event_bus = self._create_event_bus(name, account_id, region, event_source_name, tags)
        store.event_bus[event_bus.name] = event_bus

        response = CreateEventBusResponse(
            EventBusArn=event_bus.arn,
        )
        return response

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        if name == "default":
            raise InternalException("ValidationException", "Cannot delete event bus default.")
        store = self._get_store(context.account_id, context.region)
        try:
            if event_bus := self._get_event_bus(name, store):
                event_bus.delete()
                del store.event_bus[name]
        except ResourceNotFoundException as e:
            return e

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        store = self._get_store(context.account_id, context.region)
        event_buses = (
            self._get_filtered_event_buses(name_prefix, store.event_bus)
            if name_prefix
            else store.event_bus
        )
        event_buses_len = len(event_buses)
        start_index = self._decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else event_buses_len
        limited_event_buses = dict(list(event_buses.items())[start_index:end_index])

        next_token = (
            self._encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all event buses are returned
            if end_index < event_buses_len
            else None
        )

        response = {"EventBuses": event_bust_dict_to_list(limited_event_buses)}
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        name = self._extract_event_bus_name(name)
        store = self._get_store(context.account_id, context.region)
        event_bus = self._get_event_bus(name, store)
        return event_bus_dict_to_api_type_event_bus(event_bus)

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
        return {"Rules": []}  # TODO implement

    def _get_store(self, account_id: str, region: str) -> EventsStore:
        store = events_store[account_id][region]
        # create default event bus on first call
        name = "default"
        if name not in store.event_bus.keys():
            event_bus = self._create_event_bus(name, account_id, region)
            store.event_bus[event_bus.name] = event_bus

        return store

    def _create_event_bus(
        self,
        name: EventBusName,
        account_id: str,
        region: str,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
    ) -> EventBus:
        event_bus_arn = self._get_event_bus_arn(name, region, account_id)
        event_bus = EventBus(name, event_bus_arn, event_source_name, tags)
        return event_bus

    def _get_event_bus_arn(self, name: EventBusName, region: str, account_id: str) -> str:
        return f"arn:aws:events:{region}:{account_id}:event-bus/{name}"

    def _get_event_bus(self, name: EventBusName, store: EventsStore) -> EventBus:
        if name not in store.event_bus.keys():
            raise ResourceNotFoundException(f"Event bus {name} does not exist.")
        return store.event_bus[name]

    def _get_filtered_event_buses(
        self, name_prefix: EventBusName, event_buses: EventBusDict
    ) -> EventBusDict:
        return {
            name: event_bus
            for name, event_bus in event_buses.items()
            if name.startswith(name_prefix)
        }

    def _encode_next_token(self, token: int) -> NextToken:
        return base64.b64encode(token.to_bytes(128, "big")).decode("utf-8")

    def _decode_next_token(self, token: NextToken) -> int:
        return int.from_bytes(base64.b64decode(token), "big")

    def _extract_event_bus_name(
        self, event_bus_name_or_arn: EventBusNameOrArn | None
    ) -> EventBusName:
        if not event_bus_name_or_arn:
            return "default"
        return event_bus_name_or_arn.split("/")[-1]
