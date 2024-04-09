from __future__ import annotations

import base64
import logging
from typing import Optional

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.events import (
    Boolean,
    CreateEventBusResponse,
    DescribeEventBusResponse,
    DescribeRuleResponse,
    EventBusList,
    EventBusName,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    EventSourceName,
    InternalException,
    LimitMax100,
    ListEventBusesResponse,
    ListRuleNamesByTargetResponse,
    ListRulesResponse,
    ListTargetsByRuleResponse,
    NextToken,
    PutRuleResponse,
    PutTargetsResponse,
    RemoveTargetsResponse,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleResponseList,
    RuleState,
    ScheduleExpression,
    TagList,
    Target,
    TargetArn,
    TargetIdList,
    TargetList,
)
from localstack.aws.api.events import EventBus as ApiTypeEventBus
from localstack.aws.api.events import Rule as ApiTypeRule
from localstack.services.events.event_bus import EventBusWorker, EventBusWorkerDict
from localstack.services.events.models_v2 import (
    EventBus,
    EventBusDict,
    EventsStore,
    Rule,
    RuleDict,
    events_store,
)
from localstack.services.events.rule import RuleWorker, RuleWorkerDict
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class EventsProvider(EventsApi, ServiceLifecycleHook):
    def __init__(self):
        self._event_bus_workers: EventBusWorkerDict = {}
        self._rule_workers: RuleWorkerDict = {}

    ##########
    # EventBus
    ##########

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(context)
        if name in store.event_buses.keys():
            raise ResourceAlreadyExistsException(f"Event bus {name} already exists.")
        event_bus_worker = self.create_event_bus_worker(
            name, region, account_id, event_source_name, tags
        )
        store.event_buses[event_bus_worker.event_bus.name] = event_bus_worker.event_bus
        response = CreateEventBusResponse(
            EventBusArn=event_bus_worker.arn,
        )
        return response

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        if name == "default":
            raise InternalException("ValidationException", "Cannot delete event bus default.")
        store = self.get_store(context)
        try:
            if event_bus := self.get_event_bus(name, store):
                if event_bus_worker := self._event_bus_workers.pop(event_bus.arn):
                    if rules := getattr(event_bus_worker, "rules", None):
                        self._delete_rule_workers(rules)
                store.event_buses.pop(name)
        except ResourceNotFoundException as error:
            return error

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        store = self.get_store(context)
        event_buses = (
            self._get_filtered_dict(name_prefix, store.event_buses)
            if name_prefix
            else store.event_buses
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

        response = {"EventBuses": self._event_bust_dict_to_list(limited_event_buses)}
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        name = self._extract_event_bus_name(name)
        store = self.get_store(context)
        event_bus = self.get_event_bus(name, store)
        response = self._event_bus_dict_to_api_type_event_bus(event_bus)
        return response

    #######
    # Rules
    #######

    @handler("PutRule")
    def put_rule(
        self,
        context: RequestContext,
        name: RuleName,
        schedule_expression: ScheduleExpression = None,
        event_pattern: EventPattern = None,
        state: RuleState = None,
        description: RuleDescription = None,
        role_arn: RoleArn = None,
        tags: TagList = None,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutRuleResponse:
        region = context.region
        account_id = context.account_id
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        store = self.get_store(context)
        event_bus = self.get_event_bus(event_bus_name, store)
        existing_rule = getattr(event_bus, "rules", {}).get(name, None)
        targets = getattr(existing_rule, "targets", None) if existing_rule else None
        # TODO use _get_rule_worker and add logic to auto create rule worker if not exist
        rule_worker = RuleWorker(
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
        self._rule_workers[rule_worker.arn] = rule_worker
        event_bus.rules[name] = rule_worker.rule
        response = PutRuleResponse(RuleArn=rule_worker.arn)
        return response

    @handler("DeleteRule")
    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> None:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        try:
            rule = self.get_rule(name, event_bus)
            self._delete_rule_workers(rule)
            del event_bus.rules[name]
        except ResourceNotFoundException as error:
            return error

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
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rules = (
            self._get_filtered_dict(name_prefix, event_bus.rules)
            if name_prefix
            else event_bus.rules
        )
        rules_len = len(rules)
        start_index = self._decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else rules_len
        limited_rules = dict(list(rules.items())[start_index:end_index])

        next_token = (
            self._encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all rules are returned
            if end_index < rules_len
            else None
        )

        response = {"Rules": list(self._rule_dict_to_list(limited_rules))}
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("ListRuleNamesByTarget")
    def list_rule_names_by_target(
        self,
        context: RequestContext,
        target_arn: TargetArn,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRuleNamesByTargetResponse:
        raise NotImplementedError  # TODO implement

    @handler("DescribeRule")
    def describe_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> DescribeRuleResponse:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)
        response = self._rule_dict_to_api_type_rule(rule)
        if created_by := getattr(rule, "created_by", None):
            response["CreatedBy"] = created_by
        return response

    @handler("DisableRule")
    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)
        rule.state = RuleState.DISABLED

    @handler("EnableRule")
    def enable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)
        rule.state = RuleState.ENABLED

    #########
    # Targets
    #########

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutTargetsResponse:
        rule_worker = self.get_rule_worker(context, rule, event_bus_name)
        failed_entries = rule_worker.validate_targets_input(targets)
        rule_worker.add_targets(targets)
        # TODO get target worker and add
        return {"FailedEntries": failed_entries, "FailedEntryCount": len(failed_entries)}

    @handler("RemoveTargets")
    def remove_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        ids: TargetIdList,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> RemoveTargetsResponse:
        rule_worker = self.get_rule_worker(context, rule, event_bus_name)
        failed_entries = rule_worker.remove_targets(ids)
        # TODO remove target worker
        return {"FailedEntries": failed_entries, "FailedEntryCount": len(failed_entries)}

    @handler("ListTargetsByRule")
    def list_targets_by_rule(
        self,
        context: RequestContext,
        rule: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListTargetsByRuleResponse:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(rule, event_bus)
        return {"Targets": list(rule.targets.values())}

    def get_store(self, context: RequestContext) -> EventsStore:
        region = context.region
        account_id = context.account_id
        store = events_store[account_id][region]
        # create default event bus on first call
        name = "default"
        if name not in store.event_buses.keys():
            event_bus_worker = EventBusWorker(name, region, account_id)
            self._event_bus_workers[event_bus_worker.arn] = event_bus_worker
            store.event_buses[event_bus_worker.event_bus.name] = event_bus_worker.event_bus
        return store

    def get_event_bus(self, name: EventBusName, store: EventsStore) -> EventBus:
        if name not in store.event_buses.keys():
            raise ResourceNotFoundException(f"Event bus {name} does not exist.")
        return store.event_buses[name]

    def get_rule(self, name: RuleName, event_bus: EventBus) -> Rule:
        if rule := event_bus.rules.get(name):
            return rule
        raise ResourceNotFoundException(f"Rule {name} does not exist on EventBus {event_bus.name}.")

    def get_target(self, target_arn: TargetArn) -> Target:
        # TODO implement
        pass

    def get_rule_worker(
        self, context: RequestContext, rule: RuleName, event_bus_name: EventBusName
    ) -> RuleWorker:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(rule, event_bus)
        return self._rule_workers[rule.arn]

    def create_event_bus_worker(
        self,
        name: EventBusName,
        region: str,
        account_id: str,
        event_source_name: Optional[EventSourceName],
        tags: Optional[TagList],
    ) -> EventBusWorker:
        event_bus_worker = EventBusWorker(
            name,
            region,
            account_id,
            event_source_name,
            tags,
        )
        self._event_bus_workers[event_bus_worker.arn] = event_bus_worker
        return event_bus_worker

    def _get_filtered_dict(self, name_prefix: str, input_dict: dict) -> dict:
        return {name: value for name, value in input_dict.items() if name.startswith(name_prefix)}

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

    def _event_bus_dict_to_api_type_event_bus(self, event_bus: EventBus) -> ApiTypeEventBus:
        if event_bus.policy:
            event_bus = {
                "Name": event_bus.name,
                "Arn": event_bus.arn,
                "Policy": event_bus.policy,
            }
        else:
            event_bus = {
                "Name": event_bus.name,
                "Arn": event_bus.arn,
            }
        return event_bus

    def _event_bust_dict_to_list(self, event_buses: EventBusDict) -> EventBusList:
        event_bus_list = [
            self._event_bus_dict_to_api_type_event_bus(event_bus)
            for event_bus in event_buses.values()
        ]
        return event_bus_list

    def _delete_rule_workers(self, rules: RuleDict | Rule) -> None:
        if isinstance(rules, Rule):
            rules = {rules.name: rules}
        for rule in rules.values():
            self._rule_workers.pop(rule.arn)

    def _rule_dict_to_api_type_rule(self, rule: Rule) -> ApiTypeRule:
        rule = {
            "Name": rule.name,
            "Arn": rule.arn,
            "EventPattern": rule.event_pattern,
            "State": rule.state,
            "Description": rule.description,
            "ScheduleExpression": rule.schedule_expression,
            "RoleArn": rule.role_arn,
            "ManagedBy": rule.managed_by,
            "EventBusName": rule.event_bus_name,
        }
        return {k: v for k, v in rule.items() if v is not None and v != {} and v != []}

    def _rule_dict_to_list(self, rules: RuleDict) -> RuleResponseList:
        rule_list = [self._rule_dict_to_api_type_rule(rule) for rule in rules.values()]
        return rule_list
