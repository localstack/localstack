import base64
import json
import logging
import re
from typing import Callable, Optional

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.config import TagsList
from localstack.aws.api.events import (
    Action,
    ArchiveDescription,
    ArchiveName,
    ArchiveResponseList,
    ArchiveState,
    Arn,
    Boolean,
    CancelReplayResponse,
    Condition,
    CreateArchiveResponse,
    CreateEventBusResponse,
    DeadLetterConfig,
    DeleteArchiveResponse,
    DescribeArchiveResponse,
    DescribeEventBusResponse,
    DescribeReplayResponse,
    DescribeRuleResponse,
    EndpointId,
    EventBusDescription,
    EventBusList,
    EventBusName,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    EventSourceName,
    InternalException,
    InvalidEventPatternException,
    KmsKeyIdentifier,
    LimitMax100,
    ListArchivesResponse,
    ListEventBusesResponse,
    ListReplaysResponse,
    ListRuleNamesByTargetResponse,
    ListRulesResponse,
    ListTagsForResourceResponse,
    ListTargetsByRuleResponse,
    NextToken,
    NonPartnerEventBusName,
    Principal,
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
    ReplayDescription,
    ReplayDestination,
    ReplayList,
    ReplayName,
    ReplayState,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RetentionDays,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleResponseList,
    RuleState,
    ScheduleExpression,
    StartReplayResponse,
    StatementId,
    String,
    TagKeyList,
    TagList,
    TagResourceResponse,
    Target,
    TargetArn,
    TargetId,
    TargetIdList,
    TargetList,
    TestEventPatternResponse,
    Timestamp,
    UntagResourceResponse,
    UpdateArchiveResponse,
)
from localstack.aws.api.events import Archive as ApiTypeArchive
from localstack.aws.api.events import EventBus as ApiTypeEventBus
from localstack.aws.api.events import Replay as ApiTypeReplay
from localstack.aws.api.events import Rule as ApiTypeRule
from localstack.services.events.archive import ArchiveService, ArchiveServiceDict
from localstack.services.events.event_bus import EventBusService, EventBusServiceDict
from localstack.services.events.event_ruler import matches_rule
from localstack.services.events.models import (
    Archive,
    ArchiveDict,
    EventBus,
    EventBusDict,
    EventsStore,
    FormattedEvent,
    Replay,
    ReplayDict,
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
from localstack.services.events.replay import ReplayService, ReplayServiceDict
from localstack.services.events.rule import RuleService, RuleServiceDict
from localstack.services.events.scheduler import JobScheduler
from localstack.services.events.target import (
    TargetSender,
    TargetSenderDict,
    TargetSenderFactory,
)
from localstack.services.events.utils import (
    extract_event_bus_name,
    extract_region_and_account_id,
    format_event,
    get_resource_type,
    get_trace_header_encoded_region_account,
    is_archive_arn,
    recursive_remove_none_values_from_dict,
    to_json_str,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.common import truncate
from localstack.utils.strings import long_uid
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp

LOG = logging.getLogger(__name__)

ARCHIVE_TARGET_ID_NAME_PATTERN = re.compile(r"^Events-Archive-(?P<name>[a-zA-Z0-9_-]+)$")


def decode_next_token(token: NextToken) -> int:
    """Decode a pagination token from base64 to integer."""
    return int.from_bytes(base64.b64decode(token), "big")


def encode_next_token(token: int) -> NextToken:
    """Encode a pagination token to base64 from integer."""
    return base64.b64encode(token.to_bytes(128, "big")).decode("utf-8")


def get_filtered_dict(name_prefix: str, input_dict: dict) -> dict:
    """Filter dictionary by prefix."""
    return {name: value for name, value in input_dict.items() if name.startswith(name_prefix)}


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
        self._archive_service_store: ArchiveServiceDict = {}
        self._replay_service_store: ReplayServiceDict = {}

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
        store = self.get_store(region, account_id)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
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
        name = extract_event_bus_name(name)
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(name, store)

        response = self._event_bus_to_api_type_event_bus(event_bus)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_buses = (
            get_filtered_dict(name_prefix, store.event_buses) if name_prefix else store.event_buses
        )
        limited_event_buses, next_token = self._get_limited_dict_and_next_token(
            event_buses, next_token, limit
        )

        response = ListEventBusesResponse(
            EventBuses=self._event_bust_dict_to_event_bus_response_list(limited_event_buses)
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("PutPermission")
    def put_permission(
        self,
        context: RequestContext,
        event_bus_name: NonPartnerEventBusName = None,
        action: Action = None,
        principal: Principal = None,
        statement_id: StatementId = None,
        condition: Condition = None,
        policy: String = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(event_bus_name, store)
        event_bus_service = self._event_bus_services_store[event_bus.arn]
        event_bus_service.put_permission(action, principal, statement_id, condition, policy)

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        statement_id: StatementId = None,
        remove_all_permissions: Boolean = None,
        event_bus_name: NonPartnerEventBusName = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(event_bus_name, store)
        event_bus_service = self._event_bus_services_store[event_bus.arn]
        if remove_all_permissions:
            event_bus_service.event_bus.policy = None
            return
        if not statement_id:
            raise ValidationException("Parameter StatementId is required.")
        event_bus_service.revoke_put_events_permission(statement_id)

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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)

        response = self._rule_to_api_type_rule(rule)
        return response

    @handler("DisableRule")
    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rules = get_filtered_dict(name_prefix, event_bus.rules) if name_prefix else event_bus.rules
        limited_rules, next_token = self._get_limited_dict_and_next_token(rules, next_token, limit)

        response = ListRulesResponse(
            Rules=list(self._rule_dict_to_rule_response_list(limited_rules))
        )
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
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        rule_service = self.get_rule_service(region, account_id, rule, event_bus_name)
        failed_entries = rule_service.add_targets(targets)
        rule_arn = rule_service.arn
        rule_name = rule_service.rule.name
        for target in targets:  # TODO only add successful targets
            self.create_target_sender(target, rule_arn, rule_name, region, account_id)

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
        region = context.region
        account_id = context.account_id
        rule_service = self.get_rule_service(region, account_id, rule, event_bus_name)
        failed_entries = rule_service.remove_targets(ids)
        self._delete_target_sender(ids, rule_service.rule)

        response = RemoveTargetsResponse(
            FailedEntryCount=len(failed_entries), FailedEntries=failed_entries
        )
        return response

    #########
    # Archive
    #########
    @handler("CreateArchive")
    def create_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        event_source_arn: Arn,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
        **kwargs,
    ) -> CreateArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if archive_name in store.archives.keys():
            raise ResourceAlreadyExistsException(f"Archive {archive_name} already exists.")
        self._check_event_bus_exists(event_source_arn, store)
        archive_service = self.create_archive_service(
            archive_name,
            region,
            account_id,
            event_source_arn,
            description,
            event_pattern,
            retention_days,
        )
        store.archives[archive_service.archive.name] = archive_service.archive

        response = CreateArchiveResponse(
            ArchiveArn=archive_service.arn,
            State=archive_service.state,
            CreationTime=archive_service.creation_time,
        )
        return response

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DeleteArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if archive := self.get_archive(archive_name, store):
            try:
                archive_service = self._archive_service_store.pop(archive.arn)
                archive_service.delete()
                del store.archives[archive_name]
            except ResourceNotFoundException as error:
                return error

    @handler("DescribeArchive")
    def describe_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DescribeArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        archive = self.get_archive(archive_name, store)

        response = self._archive_to_describe_archive_response(archive)
        return response

    @handler("ListArchives")
    def list_archives(
        self,
        context: RequestContext,
        name_prefix: ArchiveName = None,
        event_source_arn: Arn = None,
        state: ArchiveState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListArchivesResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if event_source_arn:
            self._check_event_bus_exists(event_source_arn, store)
            archives = {
                key: archive
                for key, archive in store.archives.items()
                if archive.event_source_arn == event_source_arn
            }
        elif name_prefix:
            archives = get_filtered_dict(name_prefix, store.archives)
        else:
            archives = store.archives
        limited_archives, next_token = self._get_limited_dict_and_next_token(
            archives, next_token, limit
        )

        response = ListArchivesResponse(
            Archives=list(self._archive_dict_to_archive_response_list(limited_archives))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("UpdateArchive")
    def update_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
        **kwargs,
    ) -> UpdateArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        try:
            archive = self.get_archive(archive_name, store)
        except ResourceNotFoundException:
            raise InternalException("Service encountered unexpected problem. Please try again.")
        archive_service = self._archive_service_store[archive.arn]
        archive_service.update(description, event_pattern, retention_days)

        response = UpdateArchiveResponse(
            ArchiveArn=archive_service.arn,
            State=archive.state,
            # StateReason=archive.state_reason,
            CreationTime=archive.creation_time,
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
        if len(entries) > 10:
            formatted_entries = [self._event_to_error_type_event(entry) for entry in entries]
            formatted_entries = f"[{', '.join(formatted_entries)}]"
            raise ValidationException(
                f"1 validation error detected: Value '{formatted_entries}' at 'entries' failed to satisfy constraint: Member must have length less than or equal to 10"
            )
        entries, failed_entry_count = self._process_entries(context, entries)

        response = PutEventsResponse(
            Entries=entries,
            FailedEntryCount=failed_entry_count,
        )
        return response

    @handler("PutPartnerEvents")
    def put_partner_events(
        self,
        context: RequestContext,
        entries: PutPartnerEventsRequestEntryList,
        **kwargs,
    ) -> PutPartnerEventsResponse:
        raise NotImplementedError

    ########
    # Replay
    ########

    @handler("CancelReplay")
    def cancel_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> CancelReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        replay = self.get_replay(replay_name, store)
        replay_service = self._replay_service_store[replay.arn]
        replay_service.stop()
        response = CancelReplayResponse(
            ReplayArn=replay_service.arn,
            State=replay_service.state,
            # StateReason=replay_service.state_reason,
        )
        return response

    @handler("DescribeReplay")
    def describe_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> DescribeReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        replay = self.get_replay(replay_name, store)

        response = self._replay_to_describe_replay_response(replay)
        return response

    @handler("ListReplays")
    def list_replays(
        self,
        context: RequestContext,
        name_prefix: ReplayName = None,
        state: ReplayState = None,
        event_source_arn: Arn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListReplaysResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if event_source_arn:
            replays = {
                key: replay
                for key, replay in store.replays.items()
                if replay.event_source_arn == event_source_arn
            }
        elif name_prefix:
            replays = get_filtered_dict(name_prefix, store.replays)
        else:
            replays = store.replays
        limited_replays, next_token = self._get_limited_dict_and_next_token(
            replays, next_token, limit
        )

        response = ListReplaysResponse(
            Replays=list(self._replay_dict_to_replay_response_list(limited_replays))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("StartReplay")
    def start_replay(
        self,
        context: RequestContext,
        replay_name: ReplayName,
        event_source_arn: Arn,  # Archive Arn
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        destination: ReplayDestination,
        description: ReplayDescription = None,
        **kwargs,
    ) -> StartReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if replay_name in store.replays.keys():
            raise ResourceAlreadyExistsException(f"Replay {replay_name} already exists.")
        self._validate_replay_time(event_start_time, event_end_time)
        if event_source_arn not in self._archive_service_store:
            archive_name = event_source_arn.split("/")[-1]
            raise ValidationException(
                f"Parameter EventSourceArn is not valid. Reason: Archive {archive_name} does not exist."
            )
        self._validate_replay_destination(destination, event_source_arn)
        replay_service = self.create_replay_service(
            replay_name,
            region,
            account_id,
            event_source_arn,
            destination,
            event_start_time,
            event_end_time,
            description,
        )
        store.replays[replay_service.replay.name] = replay_service.replay
        archive_service = self._archive_service_store[event_source_arn]
        events_to_replay = archive_service.get_events(
            replay_service.event_start_time, replay_service.event_end_time
        )
        replay_service.start(events_to_replay)
        if events_to_replay:
            re_formatted_event_to_replay = replay_service.re_format_events_from_archive(
                events_to_replay, replay_name
            )
            self._process_entries(context, re_formatted_event_to_replay)
        replay_service.finish()

        response = StartReplayResponse(
            ReplayArn=replay_service.arn,
            State=replay_service.state,
            StateReason=replay_service.state_reason,
            ReplayStartTime=replay_service.replay_start_time,
        )
        return response

    ######
    # Tags
    ######

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        check_unique_tags(tags)
        store.TAGS.tag_resource(resource_arn, tags)

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        store.TAGS.untag_resource(resource_arn, tag_keys)

    #########
    # Methods
    #########

    def get_store(self, region: str, account_id: str) -> EventsStore:
        """Returns the events store for the account and region.
        On first call, creates the default event bus for the account region."""
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

    def get_archive(self, name: ArchiveName, store: EventsStore) -> Archive:
        if archive := store.archives.get(name):
            return archive
        raise ResourceNotFoundException(f"Archive {name} does not exist.")

    def get_replay(self, name: ReplayName, store: EventsStore) -> Replay:
        if replay := store.replays.get(name):
            return replay
        raise ResourceNotFoundException(f"Replay {name} does not exist.")

    def get_rule_service(
        self,
        region: str,
        account_id: str,
        rule_name: RuleName,
        event_bus_name: EventBusName,
    ) -> RuleService:
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
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
        self, target: Target, rule_arn: Arn, rule_name: RuleName, region: str, account_id: str
    ) -> TargetSender:
        target_sender = TargetSenderFactory(
            target, rule_arn, rule_name, region, account_id
        ).get_target_sender()
        self._target_sender_store[target_sender.arn] = target_sender
        return target_sender

    def create_archive_service(
        self,
        archive_name: ArchiveName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        description: ArchiveDescription,
        event_pattern: EventPattern,
        retention_days: RetentionDays,
    ) -> ArchiveService:
        archive_service = ArchiveService(
            archive_name,
            region,
            account_id,
            event_source_arn,
            description,
            event_pattern,
            retention_days,
        )
        self._archive_service_store[archive_service.arn] = archive_service
        return archive_service

    def create_replay_service(
        self,
        name: ReplayName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        destination: ReplayDestination,
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        description: ReplayDescription,
    ) -> ReplayService:
        replay_service = ReplayService(
            name,
            region,
            account_id,
            event_source_arn,
            destination,
            event_start_time,
            event_end_time,
            description,
        )
        self._replay_service_store[replay_service.arn] = replay_service
        return replay_service

    def _delete_rule_services(self, rules: RuleDict | Rule) -> None:
        """
        Delete all rule services associated to the input from the store.
        Accepts a single Rule object or a dict of Rule objects as input.
        """
        if isinstance(rules, Rule):
            rules = {rules.name: rules}
        for rule in rules.values():
            del self._rule_services_store[rule.arn]

    def _delete_target_sender(self, ids: TargetIdList, rule) -> None:
        for target_id in ids:
            if target := rule.targets.get(target_id):
                target_arn = target["Arn"]
                try:
                    del self._target_sender_store[target_arn]
                except KeyError:
                    LOG.error(f"Error deleting target service {target_arn}.")

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

    def _check_resource_exists(
        self, resource_arn: Arn, resource_type: ResourceType, store: EventsStore
    ) -> None:
        if resource_type == ResourceType.EVENT_BUS:
            event_bus_name = extract_event_bus_name(resource_arn)
            self.get_event_bus(event_bus_name, store)
        if resource_type == ResourceType.RULE:
            event_bus_name = extract_event_bus_name(resource_arn)
            event_bus = self.get_event_bus(event_bus_name, store)
            rule_name = resource_arn.split("/")[-1]
            self.get_rule(rule_name, event_bus)

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

    def _check_event_bus_exists(
        self, event_bus_name_or_arn: EventBusNameOrArn, store: EventsStore
    ) -> None:
        event_bus_name = extract_event_bus_name(event_bus_name_or_arn)
        self.get_event_bus(event_bus_name, store)

    def _validate_replay_time(self, event_start_time: Timestamp, event_end_time: Timestamp) -> None:
        if event_end_time <= event_start_time:
            raise ValidationException(
                "Parameter EventEndTime is not valid. Reason: EventStartTime must be before EventEndTime."
            )

    def _validate_replay_destination(
        self, destination: ReplayDestination, event_source_arn: Arn
    ) -> None:
        archive_service = self._archive_service_store[event_source_arn]
        if destination_arn := destination.get("Arn"):
            if destination_arn != archive_service.archive.event_source_arn:
                if destination_arn in self._event_bus_services_store.keys():
                    raise ValidationException(
                        "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted."
                    )
                else:
                    event_bus_name = extract_event_bus_name(destination_arn)
                    raise ResourceNotFoundException(f"Event bus {event_bus_name} does not exist.")

    # Internal type to API type remappings

    def _event_bust_dict_to_event_bus_response_list(
        self, event_buses: EventBusDict
    ) -> EventBusList:
        """Return a converted dict of EventBus model objects as a list of event buses in API type EventBus format."""
        event_bus_list = [
            self._event_bus_to_api_type_event_bus(event_bus) for event_bus in event_buses.values()
        ]
        return event_bus_list

    def _event_bus_to_api_type_event_bus(self, event_bus: EventBus) -> ApiTypeEventBus:
        event_bus_api_type = {
            "Name": event_bus.name,
            "Arn": event_bus.arn,
        }
        if event_bus.creation_time:
            event_bus_api_type["CreationTime"] = event_bus.creation_time
        if event_bus.last_modified_time:
            event_bus_api_type["LastModifiedTime"] = event_bus.last_modified_time
        if event_bus.policy:
            event_bus_api_type["Policy"] = recursive_remove_none_values_from_dict(event_bus.policy)

        return event_bus_api_type

    def _event_to_error_type_event(self, entry: PutEventsRequestEntry) -> str:
        detail = (
            json.dumps(json.loads(entry["Detail"]), separators=(", ", ": "))
            if entry.get("Detail")
            else "null"
        )
        return (
            f"PutEventsRequestEntry("
            f"time={entry.get('Time', 'null')}, "
            f"source={entry.get('Source', 'null')}, "
            f"resources={entry.get('Resources', 'null')}, "
            f"detailType={entry.get('DetailType', 'null')}, "
            f"detail={detail}, "
            f"eventBusName={entry.get('EventBusName', 'null')}, "
            f"traceHeader={entry.get('TraceHeader', 'null')}, "
            f"kmsKeyIdentifier={entry.get('kmsKeyIdentifier', 'null')}, "
            f"internalMetadata={entry.get('internalMetadata', 'null')}"
            f")"
        )

    def _rule_dict_to_rule_response_list(self, rules: RuleDict) -> RuleResponseList:
        """Return a converted dict of Rule model objects as a list of rules in API type Rule format."""
        rule_list = [self._rule_to_api_type_rule(rule) for rule in rules.values()]
        return rule_list

    def _rule_to_api_type_rule(self, rule: Rule) -> ApiTypeRule:
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

    def _archive_dict_to_archive_response_list(self, archives: ArchiveDict) -> ArchiveResponseList:
        """Return a converted dict of Archive model objects as a list of archives in API type Archive format."""
        archive_list = [self._archive_to_api_type_archive(archive) for archive in archives.values()]
        return archive_list

    def _archive_to_api_type_archive(self, archive: Archive) -> ApiTypeArchive:
        archive = {
            "ArchiveName": archive.name,
            "EventSourceArn": archive.event_source_arn,
            "State": archive.state,
            # TODO add "StateReason": archive.state_reason,
            "RetentionDays": archive.retention_days,
            "SizeBytes": archive.size_bytes,
            "EventCount": archive.event_count,
            "CreationTime": archive.creation_time,
        }
        return {key: value for key, value in archive.items() if value is not None}

    def _archive_to_describe_archive_response(self, archive: Archive) -> DescribeArchiveResponse:
        archive_dict = {
            "ArchiveArn": archive.arn,
            "ArchiveName": archive.name,
            "EventSourceArn": archive.event_source_arn,
            "State": archive.state,
            # TODO add "StateReason": archive.state_reason,
            "RetentionDays": archive.retention_days,
            "SizeBytes": archive.size_bytes,
            "EventCount": archive.event_count,
            "CreationTime": archive.creation_time,
            "EventPattern": archive.event_pattern,
            "Description": archive.description,
        }
        return {key: value for key, value in archive_dict.items() if value is not None}

    def _replay_dict_to_replay_response_list(self, replays: ReplayDict) -> ReplayList:
        """Return a converted dict of Replay model objects as a list of replays in API type Replay format."""
        replay_list = [self._replay_to_api_type_replay(replay) for replay in replays.values()]
        return replay_list

    def _replay_to_api_type_replay(self, replay: Replay) -> ApiTypeReplay:
        replay = {
            "ReplayName": replay.name,
            "EventSourceArn": replay.event_source_arn,
            "State": replay.state,
            # # "StateReason": replay.state_reason,
            "EventStartTime": replay.event_start_time,
            "EventEndTime": replay.event_end_time,
            "EventLastReplayedTime": replay.event_last_replayed_time,
            "ReplayStartTime": replay.replay_start_time,
            "ReplayEndTime": replay.replay_end_time,
        }
        return {key: value for key, value in replay.items() if value is not None}

    def _replay_to_describe_replay_response(self, replay: Replay) -> DescribeReplayResponse:
        replay_dict = {
            "ReplayName": replay.name,
            "ReplayArn": replay.arn,
            "Description": replay.description,
            "State": replay.state,
            # # "StateReason": replay.state_reason,
            "EventSourceArn": replay.event_source_arn,
            "Destination": replay.destination,
            "EventStartTime": replay.event_start_time,
            "EventEndTime": replay.event_end_time,
            "EventLastReplayedTime": replay.event_last_replayed_time,
            "ReplayStartTime": replay.replay_start_time,
            "ReplayEndTime": replay.replay_end_time,
        }
        return {key: value for key, value in replay_dict.items() if value is not None}

    def _put_to_archive(
        self,
        region: str,
        account_id: str,
        archive_target_id: str,
        event: FormattedEvent,
    ) -> None:
        archive_name = ARCHIVE_TARGET_ID_NAME_PATTERN.match(archive_target_id).group("name")

        store = self.get_store(region, account_id)
        archive = self.get_archive(archive_name, store)
        archive_service = self._archive_service_store[archive.arn]
        archive_service.put_events([event])

    def _process_entries(
        self, context: RequestContext, entries: PutEventsRequestEntryList
    ) -> tuple[PutEventsResultEntryList, int]:
        """Main method to process events put to an event bus.
        Events are validated to contain the proper fields and formatted.
        Events are matched against all the rules of the respective event bus.
        For matching rules the event is either sent to the respective target,
        via the target sender put to the defined archived."""
        processed_entries = []
        failed_entry_count = 0
        for event in entries:
            event_bus_name_or_arn = event.get("EventBusName", "default")
            event_bus_name = extract_event_bus_name(event_bus_name_or_arn)
            if event_failed_validation := validate_event(event):
                processed_entries.append(event_failed_validation)
                failed_entry_count += 1
                continue
            region, account_id = extract_region_and_account_id(event_bus_name_or_arn, context)
            if encoded_trace_header := get_trace_header_encoded_region_account(
                event, context.region, context.account_id, region, account_id
            ):
                event["TraceHeader"] = encoded_trace_header
            event_formatted = format_event(event, region, account_id)
            store = self.get_store(region, account_id)
            try:
                event_bus = self.get_event_bus(event_bus_name, store)
            except ResourceNotFoundException:
                # ignore events for non-existing event buses but add processed event
                processed_entries.append({"EventId": event_formatted["id"]})
                continue
            matching_rules = [rule for rule in event_bus.rules.values()]
            for rule in matching_rules:
                event_pattern = rule.event_pattern
                event_str = to_json_str(event_formatted)
                if matches_rule(event_str, event_pattern):
                    for target in rule.targets.values():
                        target_arn = target["Arn"]
                        if is_archive_arn(target_arn):
                            self._put_to_archive(
                                region,
                                account_id,
                                archive_target_id=target["Id"],
                                event=event_formatted,
                            )
                        else:
                            target_sender = self._target_sender_store[target_arn]
                            try:
                                target_sender.process_event(event_formatted)
                                processed_entries.append({"EventId": event_formatted["id"]})
                            except Exception as error:
                                processed_entries.append(
                                    {
                                        "ErrorCode": "InternalException",
                                        "ErrorMessage": str(error),
                                    }
                                )
                                failed_entry_count += 1
        return processed_entries, failed_entry_count
