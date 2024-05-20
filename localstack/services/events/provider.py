import base64
import json
import logging
import re
from datetime import datetime, timezone
from typing import Callable, Optional

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.config import TagsList
from localstack.aws.api.events import (
    Arn,
    Boolean,
    CreateEventBusResponse,
    DeadLetterConfig,
    DescribeEventBusResponse,
    DescribeRuleResponse,
    EndpointId,
    EventBusDescription,
    EventBusList,
    EventBusName,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    EventSourceName,
    InvalidEventPatternException,
    KmsKeyIdentifier,
    LimitMax100,
    ListEventBusesResponse,
    ListRuleNamesByTargetResponse,
    ListRulesResponse,
    ListTagsForResourceResponse,
    ListTargetsByRuleResponse,
    NextToken,
    PutEventsRequestEntry,
    PutEventsRequestEntryList,
    PutEventsResponse,
    PutEventsResultEntry,
    PutEventsResultEntryList,
    PutPartnerEventsRequestEntryList,
    PutPartnerEventsResponse,
    PutRuleResponse,
    PutTargetsResponse,
    RemoveTargetsResponse,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RoleArn,
    RuleArn,
    RuleDescription,
    RuleName,
    RuleResponseList,
    RuleState,
    ScheduleExpression,
    TagKeyList,
    TagList,
    TagResourceResponse,
    Target,
    TargetArn,
    TargetId,
    TargetIdList,
    TargetList,
    TestEventPatternResponse,
    UntagResourceResponse,
)
from localstack.aws.api.events import EventBus as ApiTypeEventBus
from localstack.aws.api.events import Rule as ApiTypeRule
from localstack.services.events.event_bus import EventBusService, EventBusServiceDict
from localstack.services.events.event_ruler import matches_rule
from localstack.services.events.models import (
    EventBus,
    EventBusDict,
    EventsStore,
    FormattedEvent,
    ResourceType,
    Rule,
    RuleDict,
    TargetDict,
    ValidationException,
    events_store,
)
from localstack.services.events.models import (
    InvalidEventPatternException as InternalInvalidEventPatternException,
)
from localstack.services.events.rule import RuleService, RuleServiceDict
from localstack.services.events.scheduler import JobScheduler
from localstack.services.events.target import TargetSender, TargetSenderDict, TargetSenderFactory
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import parse_arn
from localstack.utils.common import truncate
from localstack.utils.strings import long_uid
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp

LOG = logging.getLogger(__name__)

RULE_ARN_CUSTOM_EVENT_BUS_PATTERN = re.compile(
    r"^arn:aws:events:[a-z0-9-]+:\d{12}:rule/[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$"
)


def decode_next_token(token: NextToken) -> int:
    """Decode a pagination token from base64 to integer."""
    return int.from_bytes(base64.b64decode(token), "big")


def encode_next_token(token: int) -> NextToken:
    """Encode a pagination token to base64 from integer."""
    return base64.b64encode(token.to_bytes(128, "big")).decode("utf-8")


def get_filtered_dict(name_prefix: str, input_dict: dict) -> dict:
    """Filter dictionary by prefix."""
    return {name: value for name, value in input_dict.items() if name.startswith(name_prefix)}


def get_event_time(event: PutEventsRequestEntry) -> str:
    event_time = datetime.now(timezone.utc)
    if event_timestamp := event.get("Time"):
        try:
            # use time from event if provided
            event_time = event_timestamp.replace(tzinfo=timezone.utc)
        except ValueError:
            # use current time if event time is invalid
            LOG.debug(
                "Could not parse the `Time` parameter, falling back to current time for the following Event: '%s'",
                event,
            )
    formatted_time_string = event_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    return formatted_time_string


def validate_event(event: PutEventsRequestEntry) -> None | PutEventsResultEntry:
    if not event.get("Source"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter Source is not valid. Reason: Source is a required argument.",
        }
    elif not event.get("DetailType"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter DetailType is not valid. Reason: DetailType is a required argument.",
        }
    elif not event.get("Detail"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter Detail is not valid. Reason: Detail is a required argument.",
        }


def format_event(event: PutEventsRequestEntry, region: str, account_id: str) -> FormattedEvent:
    # See https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html
    formatted_event = {
        "version": "0",
        "id": str(long_uid()),
        "detail-type": event.get("DetailType"),
        "source": event.get("Source"),
        "account": account_id,
        "time": get_event_time(event),
        "region": region,
        "resources": event.get("Resources", []),
        "detail": json.loads(event.get("Detail", "{}")),
    }

    return formatted_event


def get_resource_type(arn: Arn) -> ResourceType:
    parsed_arn = parse_arn(arn)
    resource_type = parsed_arn["resource"].split("/", 1)[0]
    if resource_type == "event-bus":
        return ResourceType.EVENT_BUS
    if resource_type == "rule":
        return ResourceType.RULE
    raise ValidationException(
        f"Parameter {arn} is not valid. Reason: Provided Arn is not in correct format."
    )


def check_unique_tags(tags: TagsList) -> None:
    unique_tag_keys = {tag["Key"] for tag in tags}
    if len(unique_tag_keys) < len(tags):
        raise ValidationException("Invalid parameter: Duplicated keys are not allowed.")


class EventsProvider(EventsApi, ServiceLifecycleHook):
    # api methods are grouped by resource type and sorted in hierarchical order
    # each group is sorted alphabetically
    def __init__(self):
        self._event_bus_services_store: EventBusServiceDict = {}
        self._rule_services_store: RuleServiceDict = {}
        self._target_sender_store: TargetSenderDict = {}

    def on_before_start(self):
        JobScheduler.start()

    def on_before_stop(self):
        JobScheduler.shutdown()

    ##########
    # EventBus
    ##########

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        description: EventBusDescription = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        dead_letter_config: DeadLetterConfig = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(context)
        if name in store.event_buses.keys():
            raise ResourceAlreadyExistsException(f"Event bus {name} already exists.")
        event_bus_service = self.create_event_bus_service(
            name, region, account_id, event_source_name, tags
        )
        store.event_buses[event_bus_service.event_bus.name] = event_bus_service.event_bus

        if tags:
            self.tag_resource(context, event_bus_service.arn, tags)

        response = CreateEventBusResponse(
            EventBusArn=event_bus_service.arn,
        )
        return response

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        if name == "default":
            raise ValidationException("Cannot delete event bus default.")
        store = self.get_store(context)
        try:
            if event_bus := self.get_event_bus(name, store):
                del self._event_bus_services_store[event_bus.arn]
                if rules := event_bus.rules:
                    self._delete_rule_services(rules)
                del store.event_buses[name]
                del store.TAGS[event_bus.arn]
        except ResourceNotFoundException as error:
            return error

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        name = self._extract_event_bus_name(name)
        store = self.get_store(context)
        event_bus = self.get_event_bus(name, store)

        response = self._event_bus_dict_to_api_type_event_bus(event_bus)
        return response

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
            get_filtered_dict(name_prefix, store.event_buses) if name_prefix else store.event_buses
        )
        limited_event_buses, next_token = self._get_limited_dict_and_next_token(
            event_buses, next_token, limit
        )

        response = ListEventBusesResponse(
            EventBuses=self._event_bust_dict_to_api_type_list(limited_event_buses)
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    #######
    # Rules
    #######
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
            if rule.targets and not force:
                raise ValidationException("Rule can't be deleted since it has targets.")
            self._delete_rule_services(rule)
            del event_bus.rules[name]
            del store.TAGS[rule.arn]
        except ResourceNotFoundException as error:
            return error

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
        rules = get_filtered_dict(name_prefix, event_bus.rules) if name_prefix else event_bus.rules
        limited_rules, next_token = self._get_limited_dict_and_next_token(rules, next_token, limit)

        response = ListRulesResponse(Rules=list(self._rule_dict_to_api_type_list(limited_rules)))
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
        raise NotImplementedError

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
        existing_rule = event_bus.rules.get(name)
        targets = existing_rule.targets if existing_rule else None
        rule_service = self.create_rule_service(
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
        event_bus.rules[name] = rule_service.rule

        if tags:
            self.tag_resource(context, rule_service.arn, tags)

        response = PutRuleResponse(RuleArn=rule_service.arn)
        return response

    @handler("TestEventPattern")
    def test_event_pattern(
        self, context: RequestContext, event_pattern: EventPattern, event: str, **kwargs
    ) -> TestEventPatternResponse:
        """Test event pattern uses EventBridge event pattern matching:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
        """
        try:
            result = matches_rule(event, event_pattern)
        except InternalInvalidEventPatternException as e:
            raise InvalidEventPatternException(e.message) from e

        return TestEventPatternResponse(Result=result)

    #########
    # Targets
    #########

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
        targets = rule.targets
        limited_targets, next_token = self._get_limited_dict_and_next_token(
            targets, next_token, limit
        )

        response = ListTargetsByRuleResponse(Targets=list(limited_targets.values()))
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutTargetsResponse:
        region = context.region
        account_id = context.account_id
        rule_service = self.get_rule_service(context, rule, event_bus_name)
        failed_entries = rule_service.add_targets(targets)
        rule_arn = rule_service.arn
        rule_name = rule_service.rule.name
        for target in targets:  # TODO only add successful targets
            self.create_target_sender(target, region, account_id, rule_arn, rule_name)

        if rule_service.schedule_cron:
            schedule_job_function = self._get_scheduled_rule_job_function(
                account_id, region, rule_service.rule
            )
            rule_service.create_schedule_job(schedule_job_function)
        response = PutTargetsResponse(
            FailedEntryCount=len(failed_entries), FailedEntries=failed_entries
        )
        return response

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
        rule_service = self.get_rule_service(context, rule, event_bus_name)
        failed_entries = rule_service.remove_targets(ids)
        self._delete_target_sender(ids, rule_service.rule)

        response = RemoveTargetsResponse(
            FailedEntryCount=len(failed_entries), FailedEntries=failed_entries
        )
        return response

    ########
    # Events
    ########

    @handler("PutEvents")
    def put_events(
        self,
        context: RequestContext,
        entries: PutEventsRequestEntryList,
        endpoint_id: EndpointId = None,
        **kwargs,
    ) -> PutEventsResponse:
        entries, failed_entry_count = self._process_entries(context, entries)

        response = PutEventsResponse(
            Entries=entries,
            FailedEntryCount=failed_entry_count,
        )
        return response

    @handler("PutPartnerEvents")
    def put_partner_events(
        self, context: RequestContext, entries: PutPartnerEventsRequestEntryList, **kwargs
    ) -> PutPartnerEventsResponse:
        raise NotImplementedError

    ######
    # Tags
    ######

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceResponse:
        store = self.get_store(context)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        tags = store.TAGS.list_tags_for_resource(resource_arn)
        return ListTagsForResourceResponse(tags)

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        # each tag key must be unique
        # https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html#tag-best-practices
        store = self.get_store(context)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        check_unique_tags(tags)
        store.TAGS.tag_resource(resource_arn, tags)

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        store = self.get_store(context)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        store.TAGS.untag_resource(resource_arn, tag_keys)

    #########
    # Methods
    #########

    def get_store(self, context: RequestContext) -> EventsStore:
        """Returns the events store for the account and region.
        On first call, creates the default event bus for the account region."""
        region = context.region
        account_id = context.account_id
        store = events_store[account_id][region]
        # create default event bus for account region on first call
        default_event_bus_name = "default"
        if default_event_bus_name not in store.event_buses.keys():
            event_bus_service = self.create_event_bus_service(
                default_event_bus_name, region, account_id, None, None
            )
            store.event_buses[event_bus_service.event_bus.name] = event_bus_service.event_bus
        return store

    def get_event_bus(self, name: EventBusName, store: EventsStore) -> EventBus:
        if event_bus := store.event_buses.get(name):
            return event_bus
        raise ResourceNotFoundException(f"Event bus {name} does not exist.")

    def get_rule(self, name: RuleName, event_bus: EventBus) -> Rule:
        if rule := event_bus.rules.get(name):
            return rule
        raise ResourceNotFoundException(f"Rule {name} does not exist on EventBus {event_bus.name}.")

    def get_target(self, target_id: TargetId, rule: Rule) -> Target:
        if target := rule.targets.get(target_id):
            return target
        raise ResourceNotFoundException(f"Target {target_id} does not exist on Rule {rule.name}.")

    def get_rule_service(
        self, context: RequestContext, rule_name: RuleName, event_bus_name: EventBusName
    ) -> RuleService:
        store = self.get_store(context)
        event_bus_name = self._extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(rule_name, event_bus)
        return self._rule_services_store[rule.arn]

    def create_event_bus_service(
        self,
        name: EventBusName,
        region: str,
        account_id: str,
        event_source_name: Optional[EventSourceName],
        tags: Optional[TagList],
    ) -> EventBusService:
        event_bus_service = EventBusService(
            name,
            region,
            account_id,
            event_source_name,
            tags,
        )
        self._event_bus_services_store[event_bus_service.arn] = event_bus_service
        return event_bus_service

    def create_rule_service(
        self,
        name: RuleName,
        region: str,
        account_id: str,
        schedule_expression: Optional[ScheduleExpression],
        event_pattern: Optional[EventPattern],
        state: Optional[RuleState],
        description: Optional[RuleDescription],
        role_arn: Optional[RoleArn],
        tags: Optional[TagList],
        event_bus_name: Optional[EventBusName],
        targets: Optional[TargetDict],
    ) -> RuleService:
        rule_service = RuleService(
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
        self._rule_services_store[rule_service.arn] = rule_service
        return rule_service

    def create_target_sender(
        self, target: Target, region: str, account_id: str, rule_arn: Arn, rule_name: RuleName
    ) -> TargetSender:
        target_sender = TargetSenderFactory(
            target, region, account_id, rule_arn, rule_name
        ).get_target_sender()
        self._target_sender_store[target_sender.arn] = target_sender
        return target_sender

    def _get_limited_dict_and_next_token(
        self, input_dict: dict, next_token: NextToken | None, limit: LimitMax100 | None
    ) -> tuple[dict, NextToken]:
        """Return a slice of the given dictionary starting from next_token with length of limit
        and new last index encoded as a next_token for pagination."""
        input_dict_len = len(input_dict)
        start_index = decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else input_dict_len
        limited_dict = dict(list(input_dict.items())[start_index:end_index])

        next_token = (
            encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all items are returned
            if end_index < input_dict_len
            else None
        )
        return limited_dict, next_token

    def _extract_event_bus_name(
        self, resource_arn_or_name: EventBusNameOrArn | RuleArn | None
    ) -> EventBusName:
        """Return the event bus name. Input can be either an event bus name or ARN."""
        if not resource_arn_or_name:
            return "default"
        if "arn:aws:events" not in resource_arn_or_name:
            return resource_arn_or_name
        resource_type = get_resource_type(resource_arn_or_name)
        # TODO how to deal with / in event bus name or rule name
        if resource_type == ResourceType.EVENT_BUS:
            return resource_arn_or_name.split("/")[-1]
        if resource_type == ResourceType.RULE:
            if bool(RULE_ARN_CUSTOM_EVENT_BUS_PATTERN.match(resource_arn_or_name)):
                return resource_arn_or_name.split("rule/", 1)[1].split("/", 1)[0]
            return "default"

    def _event_bust_dict_to_api_type_list(self, event_buses: EventBusDict) -> EventBusList:
        """Return a converted dict of EventBus model objects as a list of event buses in API type EventBus format."""
        event_bus_list = [
            self._event_bus_dict_to_api_type_event_bus(event_bus)
            for event_bus in event_buses.values()
        ]
        return event_bus_list

    def _event_bus_dict_to_api_type_event_bus(self, event_bus: EventBus) -> ApiTypeEventBus:
        event_bus_api_type = {
            "Name": event_bus.name,
            "Arn": event_bus.arn,
        }
        if event_bus.policy:
            event_bus_api_type["Policy"] = event_bus.policy

        return event_bus_api_type

    def _delete_rule_services(self, rules: RuleDict | Rule) -> None:
        """
        Delete all rule services associated to the input from the store.
        Accepts a single Rule object or a dict of Rule objects as input.
        """
        if isinstance(rules, Rule):
            rules = {rules.name: rules}
        for rule in rules.values():
            del self._rule_services_store[rule.arn]

    def _rule_dict_to_api_type_list(self, rules: RuleDict) -> RuleResponseList:
        """Return a converted dict of Rule model objects as a list of rules in API type Rule format."""
        rule_list = [self._rule_dict_to_api_type_rule(rule) for rule in rules.values()]
        return rule_list

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
            "CreatedBy": rule.created_by,
        }
        return {key: value for key, value in rule.items() if value is not None}

    def _delete_target_sender(self, ids: TargetIdList, rule) -> None:
        for target_id in ids:
            if target := rule.targets.get(target_id):
                target_arn = target["Arn"]
                try:
                    del self._target_sender_store[target_arn]
                except KeyError:
                    LOG.error(f"Error deleting target service {target_arn}.")

    def _check_resource_exists(
        self, resource_arn: Arn, resource_type: ResourceType, store: EventsStore
    ) -> None:
        if resource_type == ResourceType.EVENT_BUS:
            event_bus_name = self._extract_event_bus_name(resource_arn)
            self.get_event_bus(event_bus_name, store)
        if resource_type == ResourceType.RULE:
            event_bus_name = self._extract_event_bus_name(resource_arn)
            event_bus = self.get_event_bus(event_bus_name, store)
            rule_name = resource_arn.split("/")[-1]
            self.get_rule(rule_name, event_bus)

    def _process_entries(
        self, context: RequestContext, entries: PutEventsRequestEntryList
    ) -> tuple[PutEventsResultEntryList, int]:
        processed_entries = []
        failed_entry_count = 0
        for event in entries:
            event_bus_name = event.get("EventBusName", "default")
            if event_failed_validation := validate_event(event):
                processed_entries.append(event_failed_validation)
                failed_entry_count += 1
                continue
            event = format_event(event, context.region, context.account_id)
            store = self.get_store(context)
            try:
                event_bus = self.get_event_bus(event_bus_name, store)
            except ResourceNotFoundException:
                # ignore events for non-existing event buses but add processed event
                processed_entries.append({"EventId": event["id"]})
                continue
            matching_rules = [rule for rule in event_bus.rules.values()]
            for rule in matching_rules:
                event_pattern = rule.event_pattern
                event_str = json.dumps(event)
                if matches_rule(event_str, event_pattern):
                    for target in rule.targets.values():
                        target_sender = self._target_sender_store[target["Arn"]]
                        try:
                            target_sender.process_event(event)
                            processed_entries.append({"EventId": event["id"]})
                        except Exception as error:
                            processed_entries.append(
                                {
                                    "ErrorCode": "InternalException",
                                    "ErrorMessage": str(error),
                                }
                            )
                            failed_entry_count += 1
        return processed_entries, failed_entry_count

    def _get_scheduled_rule_job_function(self, account_id, region, rule: Rule) -> Callable:
        def func(*args, **kwargs):
            """Create custom scheduled event and send it to all targets specified by associated rule using respective TargetSender"""
            for target in rule.targets.values():
                if custom_input := target.get("Input"):
                    event = json.loads(custom_input)
                else:
                    event = {
                        "version": "0",
                        "id": long_uid(),
                        "detail-type": "Scheduled Event",
                        "source": "aws.events",
                        "account": account_id,
                        "time": timestamp(format=TIMESTAMP_FORMAT_TZ),
                        "region": region,
                        "resources": [rule.arn],
                        "detail": {},
                    }

                target_sender = self._target_sender_store[target["Arn"]]
                try:
                    target_sender.process_event(event)
                except Exception as e:
                    LOG.info(
                        "Unable to send event notification %s to target %s: %s",
                        truncate(event),
                        target,
                        e,
                    )

        return func
