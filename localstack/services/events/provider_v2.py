import logging

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.events import (
    CreateEventBusResponse,
    EventBusName,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    EventSourceName,
    PutRuleResponse,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    TagList,
)
from localstack.services.plugins import ServiceLifecycleHook

LOG = logging.getLogger(__name__)


class EventsProvider(EventsApi, ServiceLifecycleHook):
    def __init__(self):
        self._rules = {}
        self._event_buses = {}

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        event_bus_arn = f"arn:aws:events:{context.region}:{context.account_id}:event-bus/{name}"
        event_bus = {"Name": name, "Arn": event_bus_arn}
        self._event_buses[name] = event_bus

        response = CreateEventBusResponse(
            EventBusArn=event_bus_arn,
        )
        return response

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
        rule = {
            "Name": name,
            "ScheduleExpression": schedule_expression,
            "EventPattern": event_pattern,
            "State": state,
            "Description": description,
            "RoleArn": role_arn,
            "EventBusName": event_bus_name,
        }
        self._rules[name] = rule

        response = PutRuleResponse(
            RuleArn=f"arn:aws:events:{context.region}:{context.account_id}:rule/{name}",
        )
        return response
